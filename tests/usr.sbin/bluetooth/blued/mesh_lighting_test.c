/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard
 */
#include <sys/types.h>
#include <atf-c.h>
#include <string.h>

#include "mesh_lighting.h"
#include "spec_oracles.h"

#define DEFINE_LC_OPCODE_ORACLE(name, value) \
	TEST_MESH_OP_LIGHT_LC_##name = value,
enum {
	BT_ASSIGNED_MESH_LIGHT_LC_OPCODES(DEFINE_LC_OPCODE_ORACLE)
};
#undef DEFINE_LC_OPCODE_ORACLE

#define DEFINE_HSL_SETUP_OPCODE_ORACLE(name, value) \
	TEST_MESH_OP_LIGHT_HSL_##name = value,
enum {
	BT_ASSIGNED_MESH_LIGHT_HSL_SETUP_OPCODES(
	    DEFINE_HSL_SETUP_OPCODE_ORACLE)
};
#undef DEFINE_HSL_SETUP_OPCODE_ORACLE

#define DEFINE_XYL_OPCODE_ORACLE(name, value) \
	TEST_MESH_OP_LIGHT_XYL_##name = value,
enum {
	BT_ASSIGNED_MESH_LIGHT_XYL_OPCODES(DEFINE_XYL_OPCODE_ORACLE)
};
#undef DEFINE_XYL_OPCODE_ORACLE

#define DEFINE_LIGHTING_SIG2_OPCODE_ORACLE(name, value) \
	TEST_ASSIGNED_MESH_OP_LIGHT_##name = value,
enum {
	BT_ASSIGNED_MESH_LIGHTING_SIG2_OPCODES(
	    DEFINE_LIGHTING_SIG2_OPCODE_ORACLE)
};
#undef DEFINE_LIGHTING_SIG2_OPCODE_ORACLE

#define DEFINE_LIGHTING_MODEL_ORACLE(name, value) \
	TEST_ASSIGNED_MESH_MODEL_##name = value,
enum {
	BT_ASSIGNED_MESH_LIGHTING_MODEL_IDS(DEFINE_LIGHTING_MODEL_ORACLE)
};
#undef DEFINE_LIGHTING_MODEL_ORACLE

ATF_TC_WITHOUT_HEAD(assigned_opcode_contract);
ATF_TC_BODY(assigned_opcode_contract, tc)
{

	/* Bluetooth SIG Assigned Numbers, Mesh Model message opcodes. */
#define CHECK_LIGHTING_OPCODE(name, value) \
	ATF_CHECK_EQ_MSG((value), MESH_OP_LIGHT_##name, \
	    "Assigned Numbers Light " #name " opcode");
	BT_ASSIGNED_MESH_LIGHTING_SIG2_OPCODES(CHECK_LIGHTING_OPCODE)
#undef CHECK_LIGHTING_OPCODE
#define CHECK_LC_OPCODE(name, value) \
	ATF_CHECK_EQ_MSG((value), MESH_OP_LIGHT_LC_##name, \
	    "Assigned Numbers Light LC " #name " opcode");
	/* Includes the three one-octet Light LC Property opcodes. */
	BT_ASSIGNED_MESH_LIGHT_LC_OPCODES(CHECK_LC_OPCODE)
#undef CHECK_LC_OPCODE
#define CHECK_LIGHTING_MODEL(name, value) \
	ATF_CHECK_EQ_MSG((value), MESH_MODEL_##name, \
	    "Assigned Numbers " #name " model identifier");
	BT_ASSIGNED_MESH_LIGHTING_MODEL_IDS(CHECK_LIGHTING_MODEL)
#undef CHECK_LIGHTING_MODEL
}

ATF_TC_WITHOUT_HEAD(lightness_models);
ATF_TC_BODY(lightness_models, tc)
{
	struct mesh_light_lightness_srv srv;
	struct mesh_light_lightness_cli cli;
	struct mesh_light_lightness_set set;
	struct mesh_gen_onoff_srv onoff;
	struct mesh_gen_level_srv level;
	struct mesh_model models[2];
	struct mesh_element el;
	struct mesh_model_reply reply;
	struct mesh_access_pdu ap;
	uint8_t pdu[16];
	size_t plen;
	enum {
		/* Non-normative state and range sentinels. */
		TEST_LIGHTNESS_INITIAL = 1000,
		TEST_LIGHTNESS_TARGET = 1200,
		TEST_LIGHTNESS_RANGE_MIN = 500,
		TEST_LIGHTNESS_RANGE_MAX = 1500,
		TEST_LIGHTNESS_BELOW_RANGE = 400
	};

	mesh_light_xyl_srv_init(NULL, NULL);
	mesh_gen_onoff_srv_init(&onoff, MESH_GEN_OFF);
	mesh_gen_level_srv_init(&level, 0);
	mesh_light_lightness_srv_init(&srv, &onoff, &level);
	models[0] = mesh_light_lightness_srv_model(&srv);
	models[1] = mesh_light_lightness_setup_srv_model(&srv);
	memset(&el, 0, sizeof(el)); el.addr = 2; el.models = models; el.n_models = 2;
	memset(&set, 0, sizeof(set));
	set.lightness = TEST_LIGHTNESS_INITIAL;
	/* TID 1 is a non-normative transaction sentinel. */
	set.tid = 1;
	set.transition.has_transition = 1;
	/* MMDL §3.1.10.2: zero steps is an immediate transition. */
	set.transition.transition_time = 0;
	/* Delay zero means no execution delay (Table 6.51). */
	set.transition.delay = 0;
	ATF_REQUIRE_EQ(0, mesh_light_lightness_cli_actual_set(&set, 1, pdu,
	    &plen));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(pdu, plen, &ap));
	ATF_CHECK_EQ(BT_MMDL111_LIGHTNESS_SET_TRANSITION_LEN, ap.params_len);
	ATF_CHECK_EQ(0, ap.params[3]);
	ATF_CHECK_EQ(0, ap.params[4]);
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen, &reply));
	ATF_CHECK_EQ(TEST_ASSIGNED_MESH_OP_LIGHT_LIGHTNESS_STATUS,
	    reply.opcode);
	ATF_CHECK_EQ(TEST_LIGHTNESS_INITIAL, srv.actual);
	ATF_CHECK_EQ(BT_MMDL111_GENERIC_ONOFF_ON, onoff.present);
	ATF_CHECK_EQ((int16_t)(TEST_LIGHTNESS_INITIAL -
	    BT_MMDL111_GENERIC_LEVEL_ZERO_OFFSET), level.present);
	set.lightness = TEST_LIGHTNESS_TARGET;
	/* TID 2 is a distinct non-normative transaction sentinel. */
	set.tid = 2;
	set.transition.transition_time =
	    BT_MMDL111_TRANSITION_ONE_SECOND_100MS;
	ATF_REQUIRE_EQ(0, mesh_light_lightness_cli_actual_set(&set, 1, pdu,
	    &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch_at(&el, 1, 1, 2, pdu, plen,
	    &reply, 1000));
	ATF_CHECK_EQ(TEST_LIGHTNESS_INITIAL, srv.actual);
	ATF_CHECK_EQ(BT_MMDL111_LIGHTNESS_STATUS_TRANSITION_LEN,
	    reply.params_len);
	ATF_CHECK_EQ(TEST_LIGHTNESS_TARGET & 0xff, reply.params[2]);
	ATF_CHECK_EQ(TEST_LIGHTNESS_TARGET >> 8, reply.params[3]);
	ATF_REQUIRE_EQ(0, mesh_light_lightness_cli_get(
	    TEST_ASSIGNED_MESH_OP_LIGHT_LIGHTNESS_GET, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch_at(&el, 1, 1, 2, pdu, plen,
	    &reply, 1500));
	ATF_CHECK_EQ((TEST_LIGHTNESS_INITIAL + TEST_LIGHTNESS_TARGET) / 2,
	    srv.actual);
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch_at(&el, 1, 1, 2, pdu, plen,
	    &reply, 2000));
	ATF_CHECK_EQ(TEST_LIGHTNESS_TARGET, srv.actual);
	ATF_CHECK_EQ(BT_MMDL111_LIGHTNESS_STATUS_BASE_LEN, reply.params_len);
	set.transition.transition_time = BT_MMDL111_TRANSITION_STEPS_MASK;
	/* MMDL 1.1.1 §3.2.9.2: 0x3F selects DTT or immediate. */
	ATF_CHECK_EQ(0, mesh_light_lightness_cli_actual_set(&set, 1, pdu,
	    &plen));
	ATF_REQUIRE_EQ(0, mesh_light_lightness_cli_range_set(
	    TEST_LIGHTNESS_RANGE_MIN, TEST_LIGHTNESS_RANGE_MAX, 1, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen, &reply));
	ATF_CHECK_EQ(TEST_ASSIGNED_MESH_OP_LIGHT_LIGHTNESS_RANGE_STATUS,
	    reply.opcode);
	ATF_CHECK_EQ(BT_MMDL111_STATUS_SUCCESS, reply.params[0]);
	ATF_CHECK_EQ(BT_MMDL111_LIGHTNESS_RANGE_STATUS_LEN, reply.params_len);
	ATF_CHECK_EQ(TEST_LIGHTNESS_RANGE_MIN, srv.range_min);
	ATF_CHECK_EQ(TEST_LIGHTNESS_RANGE_MAX, srv.range_max);
	ATF_CHECK_EQ(-1, mesh_light_lightness_set_actual(&srv,
	    TEST_LIGHTNESS_BELOW_RANGE));
	mesh_light_lightness_cli_init(&cli);
	ATF_REQUIRE_EQ(0, mesh_light_lightness_cli_recv(&cli, reply.opcode,
	    reply.params, reply.params_len));
	ATF_CHECK_EQ(TEST_LIGHTNESS_RANGE_MIN, cli.range_min);
}

ATF_TC_WITHOUT_HEAD(ctl_models);
ATF_TC_BODY(ctl_models, tc)
{
	struct mesh_light_lightness_srv lightness;
	struct mesh_light_ctl_cli cli;
	struct mesh_light_ctl_srv ctl;
	struct mesh_light_ctl_set set;
	struct mesh_gen_onoff_srv onoff;
	struct mesh_gen_level_srv level;
	struct mesh_model models[3];
	struct mesh_element el;
	struct mesh_model_reply reply;
	struct mesh_access_pdu ap;
	uint8_t pdu[16], raw[9];
	size_t plen;
	enum {
		/* Non-normative valid state and mutation sentinels. */
		TEST_CTL_LIGHTNESS = 1000,
		TEST_CTL_TEMPERATURE = 3000,
		TEST_CTL_DELTA_UV = -10,
		TEST_CTL_TARGET_LIGHTNESS = 2000,
		TEST_CTL_TARGET_TEMPERATURE = 4000,
		TEST_CTL_DEFAULT_LIGHTNESS = 11,
		TEST_CTL_DEFAULT_DELTA_UV = 22
	};

	mesh_gen_onoff_srv_init(&onoff, MESH_GEN_OFF);
	mesh_gen_level_srv_init(&level, 0);
	mesh_light_lightness_srv_init(&lightness, &onoff, &level);
	mesh_light_ctl_srv_init(&ctl, &lightness);
	models[0] = mesh_light_ctl_srv_model(&ctl);
	models[1] = mesh_light_ctl_setup_srv_model(&ctl);
	models[2] = mesh_light_ctl_temp_srv_model(&ctl);
	ATF_CHECK_EQ(TEST_ASSIGNED_MESH_MODEL_LIGHT_CTL_SRV,
	    models[0].model_id);
	ATF_CHECK_EQ(TEST_ASSIGNED_MESH_MODEL_LIGHT_CTL_TEMP_SRV,
	    models[2].model_id);
	/* Three registered handlers are a non-normative libmesh contract. */
	ATF_CHECK_EQ(3, models[0].n_ops);
	ATF_CHECK_EQ(3, models[2].n_ops);
	memset(&el, 0, sizeof(el)); el.addr = 2; el.models = models; el.n_models = 3;
	memset(&set, 0, sizeof(set));
	set.lightness = TEST_CTL_LIGHTNESS;
	set.temperature = TEST_CTL_TEMPERATURE;
	set.delta_uv = TEST_CTL_DELTA_UV;
	/* TID 1 is a non-normative transaction sentinel. */
	set.tid = 1;
	set.transition.has_transition = 1;
	/* Zero steps and zero delay request an immediate transition. */
	set.transition.transition_time = 0;
	set.transition.delay = 0;
	ATF_REQUIRE_EQ(0, mesh_light_ctl_cli_set(&set, 1, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(pdu, plen, &ap));
	ATF_CHECK_EQ(BT_MMDL111_CTL_SET_TRANSITION_LEN, ap.params_len);
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen, &reply));
	ATF_CHECK_EQ(TEST_ASSIGNED_MESH_OP_LIGHT_CTL_STATUS, reply.opcode);
	ATF_CHECK_EQ(BT_MMDL111_CTL_STATUS_BASE_LEN, reply.params_len);
	ATF_CHECK_EQ(TEST_CTL_LIGHTNESS, lightness.actual);
	ATF_CHECK_EQ(TEST_CTL_TEMPERATURE, ctl.temperature);
	ATF_CHECK_EQ(TEST_CTL_DELTA_UV, ctl.delta_uv);
	raw[0] = TEST_CTL_LIGHTNESS & 0xff;
	raw[1] = TEST_CTL_LIGHTNESS >> 8;
	raw[2] = TEST_CTL_TEMPERATURE & 0xff;
	raw[3] = TEST_CTL_TEMPERATURE >> 8;
	raw[4] = TEST_CTL_TARGET_LIGHTNESS & 0xff;
	raw[5] = TEST_CTL_TARGET_LIGHTNESS >> 8;
	raw[6] = TEST_CTL_TARGET_TEMPERATURE & 0xff;
	raw[7] = TEST_CTL_TARGET_TEMPERATURE >> 8;
	raw[8] = BT_MMDL111_TRANSITION_ONE_SECOND;
	mesh_light_ctl_cli_init(&cli);
	ATF_REQUIRE_EQ(0, mesh_light_ctl_cli_recv(&cli,
	    TEST_ASSIGNED_MESH_OP_LIGHT_CTL_STATUS, raw,
	    BT_MMDL111_CTL_STATUS_TRANSITION_LEN));
	ATF_CHECK_EQ(1, cli.has_target);
	ATF_CHECK_EQ(TEST_CTL_TARGET_LIGHTNESS, cli.target_lightness);
	ATF_CHECK_EQ(TEST_CTL_TARGET_TEMPERATURE, cli.target_temperature);

	raw[0] = TEST_CTL_LIGHTNESS & 0xff;
	raw[1] = TEST_CTL_LIGHTNESS >> 8;
	/* Temperature zero is prohibited by MMDL §6.1.3.1, Table 6.6. */
	raw[2] = 0;
	raw[3] = 0;
	raw[4] = 0;
	raw[5] = 0;
	ctl.default_lightness = TEST_CTL_DEFAULT_LIGHTNESS;
	ctl.default_temperature = TEST_CTL_TEMPERATURE;
	ctl.default_delta_uv = TEST_CTL_DEFAULT_DELTA_UV;
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(
	    TEST_ASSIGNED_MESH_OP_LIGHT_CTL_DEFAULT_SET, raw,
	    BT_MMDL111_CTL_DEFAULT_SET_LEN, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_CHECK_EQ(-1, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen, &reply));
	ATF_CHECK_EQ(TEST_CTL_DEFAULT_LIGHTNESS, ctl.default_lightness);
	ATF_CHECK_EQ(TEST_CTL_TEMPERATURE, ctl.default_temperature);
	ATF_CHECK_EQ(TEST_CTL_DEFAULT_DELTA_UV, ctl.default_delta_uv);

	mesh_light_ctl_cli_init(&cli);
	/* Prior value is a non-normative atomicity sentinel. */
	cli.range_status = 1;
	raw[0] = BT_MMDL111_STATUS_RFU_FIRST;
	ATF_REQUIRE_EQ(-1, mesh_light_ctl_cli_recv(&cli,
	    TEST_ASSIGNED_MESH_OP_LIGHT_CTL_TEMPERATURE_RANGE_STATUS, raw,
	    BT_MMDL111_CTL_TEMPERATURE_RANGE_STATUS_LEN));
	ATF_CHECK_EQ(1, cli.range_status);
}

ATF_TC_WITHOUT_HEAD(hsl_models);
ATF_TC_BODY(hsl_models, tc)
{
	struct mesh_light_lightness_srv lightness;
	struct mesh_light_hsl_srv hsl;
	struct mesh_light_hsl_set set;
	struct mesh_gen_onoff_srv onoff;
	struct mesh_gen_level_srv level;
	struct mesh_model models[4];
	struct mesh_element el;
	struct mesh_model_reply reply;
	struct mesh_access_pdu ap;
	uint8_t pdu[16], raw[9]; size_t plen;
	enum {
		/* Non-normative valid state and range sentinels. */
		TEST_HSL_INITIAL_LIGHTNESS = 1000,
		TEST_HSL_INITIAL_HUE = 2000,
		TEST_HSL_INITIAL_SATURATION = 3000,
		TEST_HSL_TARGET_LIGHTNESS = 2000,
		TEST_HSL_TARGET_HUE = 4000,
		TEST_HSL_TARGET_SATURATION = 6000,
		TEST_HSL_WRAP_MIN = 100,
		TEST_HSL_WRAP_MAX = 1,
		TEST_HSL_SAT_MIN = 2,
		TEST_HSL_SAT_MAX = 3,
		TEST_HSL_WIDE_WRAP_MIN = 0xff00,
		TEST_HSL_WIDE_WRAP_MAX = 0x0100,
		TEST_HSL_HUE_INSIDE_WRAP = 0x0000,
		TEST_HSL_HUE_OUTSIDE_WRAP = 0x8000
	};

	mesh_gen_onoff_srv_init(&onoff, MESH_GEN_OFF);
	mesh_gen_level_srv_init(&level, 0);
	mesh_light_lightness_srv_init(&lightness, &onoff, &level);
	mesh_light_hsl_srv_init(&hsl, &lightness);
	models[0] = mesh_light_hsl_srv_model(&hsl);
	models[1] = mesh_light_hsl_setup_srv_model(&hsl);
	models[2] = mesh_light_hsl_hue_srv_model(&hsl);
	models[3] = mesh_light_hsl_sat_srv_model(&hsl);
	memset(&el,0,sizeof(el)); el.addr=2;el.models=models;el.n_models=4;
	memset(&set, 0, sizeof(set));
	set.lightness = TEST_HSL_INITIAL_LIGHTNESS;
	set.hue = TEST_HSL_INITIAL_HUE;
	set.saturation = TEST_HSL_INITIAL_SATURATION;
	/* TID 1 is a non-normative transaction sentinel. */
	set.tid = 1;
	set.transition.has_transition = 1;
	/* Zero steps and zero delay request an immediate transition. */
	set.transition.transition_time = 0;
	set.transition.delay = 0;
	ATF_REQUIRE_EQ(0, mesh_light_hsl_cli_set(&set, 1, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(pdu, plen, &ap));
	ATF_CHECK_EQ(BT_MMDL111_HSL_SET_TRANSITION_LEN, ap.params_len);
	memset(&reply,0,sizeof(reply));
	ATF_REQUIRE_EQ(0,mesh_access_dispatch(&el,1,1,2,pdu,plen,&reply));
	ATF_CHECK_EQ(TEST_ASSIGNED_MESH_OP_LIGHT_HSL_STATUS, reply.opcode);
	ATF_CHECK_EQ(TEST_HSL_INITIAL_LIGHTNESS, lightness.actual);
	ATF_CHECK_EQ(TEST_HSL_INITIAL_HUE, hsl.hue);
	ATF_CHECK_EQ(TEST_HSL_INITIAL_SATURATION, hsl.saturation);
	set.lightness = TEST_HSL_TARGET_LIGHTNESS;
	set.hue = TEST_HSL_TARGET_HUE;
	set.saturation = TEST_HSL_TARGET_SATURATION;
	/* TID 2 is a distinct non-normative transaction sentinel. */
	set.tid = 2;
	set.transition.transition_time =
	    BT_MMDL111_TRANSITION_ONE_SECOND_100MS;
	ATF_REQUIRE_EQ(0, mesh_light_hsl_cli_set(&set, 1, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch_at(&el, 1, 1, 2, pdu, plen,
	    &reply, 1000));
	ATF_REQUIRE_EQ(0, mesh_light_hsl_cli_get(
	    TEST_ASSIGNED_MESH_OP_LIGHT_HSL_TARGET_GET, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch_at(&el, 1, 1, 2, pdu, plen,
	    &reply, 1500));
	ATF_CHECK_EQ(BT_MMDL111_HSL_TARGET_STATUS_TRANSITION_LEN,
	    reply.params_len);
	ATF_CHECK_EQ(TEST_HSL_TARGET_LIGHTNESS,
	    (uint16_t)(reply.params[0] | reply.params[1] << 8));
	ATF_CHECK_EQ(TEST_HSL_TARGET_HUE,
	    (uint16_t)(reply.params[2] | reply.params[3] << 8));
	ATF_CHECK_EQ(TEST_HSL_TARGET_SATURATION,
	    (uint16_t)(reply.params[4] | reply.params[5] << 8));
	ATF_CHECK_EQ(BT_MMDL111_REMAINING_500MS, reply.params[6]);
	/* Prior values are non-normative mutation sentinels. */
	hsl.hue_min = 10;
	hsl.hue_max = 20;
	hsl.saturation_min = 30;
	hsl.saturation_max = 40;
	raw[0] = TEST_HSL_WRAP_MIN & 0xff;
	raw[1] = TEST_HSL_WRAP_MIN >> 8;
	raw[2] = TEST_HSL_WRAP_MAX & 0xff;
	raw[3] = TEST_HSL_WRAP_MAX >> 8;
	raw[4] = TEST_HSL_SAT_MIN & 0xff;
	raw[5] = TEST_HSL_SAT_MIN >> 8;
	raw[6] = TEST_HSL_SAT_MAX & 0xff;
	raw[7] = TEST_HSL_SAT_MAX >> 8;
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(
	    TEST_ASSIGNED_MESH_OP_LIGHT_HSL_RANGE_SET, raw,
	    BT_MMDL111_HSL_RANGE_SET_LEN, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen,
	    &reply));
	ATF_CHECK_EQ(TEST_ASSIGNED_MESH_OP_LIGHT_HSL_RANGE_STATUS,
	    reply.opcode);
	ATF_CHECK_EQ(BT_MMDL111_HSL_RANGE_STATUS_LEN, reply.params_len);
	ATF_CHECK_EQ(BT_MMDL111_STATUS_SUCCESS, reply.params[0]);
	ATF_CHECK_EQ(TEST_HSL_WRAP_MIN, hsl.hue_min);
	ATF_CHECK_EQ(TEST_HSL_WRAP_MAX, hsl.hue_max);
	ATF_CHECK_EQ(TEST_HSL_SAT_MIN, hsl.saturation_min);
	ATF_CHECK_EQ(TEST_HSL_SAT_MAX, hsl.saturation_max);
	/* Hue ranges may wrap across 0xFFFF→0x0000 (§6.1.4.1.3). */
	raw[0] = TEST_HSL_WIDE_WRAP_MIN & 0xff;
	raw[1] = TEST_HSL_WIDE_WRAP_MIN >> 8;
	raw[2] = TEST_HSL_WIDE_WRAP_MAX & 0xff;
	raw[3] = TEST_HSL_WIDE_WRAP_MAX >> 8;
	raw[4] = BT_MMDL111_HSL_COMPONENT_MIN & 0xff;
	raw[5] = BT_MMDL111_HSL_COMPONENT_MIN >> 8;
	raw[6] = BT_MMDL111_HSL_COMPONENT_MAX & 0xff;
	raw[7] = BT_MMDL111_HSL_COMPONENT_MAX >> 8;
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(
	    TEST_ASSIGNED_MESH_OP_LIGHT_HSL_RANGE_SET, raw,
	    BT_MMDL111_HSL_RANGE_SET_LEN, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen,
	    &reply));
	ATF_CHECK_EQ(TEST_HSL_WIDE_WRAP_MIN, hsl.hue_min);
	ATF_CHECK_EQ(TEST_HSL_WIDE_WRAP_MAX, hsl.hue_max);
	ATF_CHECK_EQ(0, mesh_light_hsl_set(&hsl, TEST_HSL_INITIAL_LIGHTNESS,
	    TEST_HSL_HUE_INSIDE_WRAP, TEST_HSL_INITIAL_SATURATION));
	ATF_CHECK_EQ(-1, mesh_light_hsl_set(&hsl, TEST_HSL_INITIAL_LIGHTNESS,
	    TEST_HSL_HUE_OUTSIDE_WRAP, TEST_HSL_INITIAL_SATURATION));
}

ATF_TC_WITHOUT_HEAD(xyl_models);
ATF_TC_BODY(xyl_models, tc)
{
	struct mesh_light_lightness_srv lightness;
	struct mesh_light_xyl_srv xyl;
	struct mesh_light_xyl_set set;
	struct mesh_gen_onoff_srv onoff;
	struct mesh_gen_level_srv level;
	struct mesh_model models[2];
	struct mesh_element el;
	struct mesh_model_reply reply;
	struct mesh_access_pdu ap;
	uint8_t pdu[16], raw[9]; size_t plen;
	enum {
		/* Non-normative valid state, range, and transaction sentinels. */
		TEST_XYL_INITIAL_LIGHTNESS = 1000,
		TEST_XYL_INITIAL_X = 2000,
		TEST_XYL_INITIAL_Y = 3000,
		TEST_XYL_TARGET_LIGHTNESS = 2000,
		TEST_XYL_TARGET_X = 4000,
		TEST_XYL_TARGET_Y = 6000,
		TEST_XYL_RANGE_X_MIN = 10,
		TEST_XYL_RANGE_X_MAX = 5000,
		TEST_XYL_RANGE_Y_MIN = 30,
		TEST_XYL_RANGE_Y_MAX = 7000,
		TEST_XYL_INVALID_X_MIN = 100,
		TEST_XYL_INVALID_X_MAX = 1,
		TEST_XYL_UNACK_LIGHTNESS = 500,
		TEST_XYL_UNACK_X = 15,
		TEST_XYL_UNACK_Y = 35,
		TEST_XYL_OUTSIDE_X = 6000
	};

	mesh_gen_onoff_srv_init(&onoff, MESH_GEN_OFF);
	mesh_gen_level_srv_init(&level, 0);
	mesh_light_lightness_srv_init(&lightness, &onoff, &level);
	mesh_light_xyl_srv_init(&xyl, &lightness);
	models[0] = mesh_light_xyl_srv_model(&xyl);
	models[1] = mesh_light_xyl_setup_srv_model(&xyl);
	memset(&el, 0, sizeof(el)); el.addr = 2; el.models = models; el.n_models = 2;
	memset(&set, 0, sizeof(set));
	set.lightness = TEST_XYL_INITIAL_LIGHTNESS;
	set.x = TEST_XYL_INITIAL_X;
	set.y = TEST_XYL_INITIAL_Y;
	/* TID 1 is a non-normative transaction sentinel. */
	set.tid = 1;
	set.transition.has_transition = 1;
	/* Zero steps and zero delay request an immediate transition. */
	set.transition.transition_time = 0;
	set.transition.delay = 0;
	ATF_REQUIRE_EQ(0, mesh_light_xyl_cli_set(&set, 1, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(pdu, plen, &ap));
	ATF_CHECK_EQ(TEST_ASSIGNED_MESH_OP_LIGHT_XYL_SET, ap.opcode);
	ATF_CHECK_EQ(BT_MMDL111_XYL_SET_TRANSITION_LEN, ap.params_len);
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen, &reply));
	ATF_CHECK_EQ(TEST_ASSIGNED_MESH_OP_LIGHT_XYL_STATUS, reply.opcode);
	ATF_CHECK_EQ(BT_MMDL111_XYL_STATUS_BASE_LEN, reply.params_len);
	ATF_CHECK_EQ(TEST_XYL_INITIAL_LIGHTNESS, lightness.actual);
	ATF_CHECK_EQ(TEST_XYL_INITIAL_X, xyl.x);
	ATF_CHECK_EQ(TEST_XYL_INITIAL_Y, xyl.y);
	set.lightness = TEST_XYL_TARGET_LIGHTNESS;
	set.x = TEST_XYL_TARGET_X;
	set.y = TEST_XYL_TARGET_Y;
	/* TID 2 is a distinct non-normative transaction sentinel. */
	set.tid = 2;
	set.transition.transition_time =
	    BT_MMDL111_TRANSITION_ONE_SECOND_100MS;
	ATF_REQUIRE_EQ(0, mesh_light_xyl_cli_set(&set, 1, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch_at(&el, 1, 1, 2, pdu, plen,
	    &reply, 1000));
	ATF_REQUIRE_EQ(0, mesh_light_xyl_cli_get(
	    TEST_ASSIGNED_MESH_OP_LIGHT_XYL_TARGET_GET, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch_at(&el, 1, 1, 2, pdu, plen,
	    &reply, 1500));
	ATF_CHECK_EQ(TEST_ASSIGNED_MESH_OP_LIGHT_XYL_TARGET_STATUS,
	    reply.opcode);
	ATF_CHECK_EQ(BT_MMDL111_XYL_TARGET_STATUS_TRANSITION_LEN,
	    reply.params_len);
	ATF_CHECK_EQ(TEST_XYL_TARGET_LIGHTNESS,
	    (uint16_t)(reply.params[0] | reply.params[1] << 8));
	ATF_CHECK_EQ(TEST_XYL_TARGET_X,
	    (uint16_t)(reply.params[2] | reply.params[3] << 8));
	ATF_CHECK_EQ(TEST_XYL_TARGET_Y,
	    (uint16_t)(reply.params[4] | reply.params[5] << 8));
	ATF_CHECK_EQ(BT_MMDL111_REMAINING_500MS, reply.params[6]);

	/* Tables 6.117/6.119 require four little-endian 16-bit bounds. */
	raw[0] = TEST_XYL_RANGE_X_MIN & 0xff;
	raw[1] = TEST_XYL_RANGE_X_MIN >> 8;
	raw[2] = TEST_XYL_RANGE_X_MAX & 0xff;
	raw[3] = TEST_XYL_RANGE_X_MAX >> 8;
	raw[4] = TEST_XYL_RANGE_Y_MIN & 0xff;
	raw[5] = TEST_XYL_RANGE_Y_MIN >> 8;
	raw[6] = TEST_XYL_RANGE_Y_MAX & 0xff;
	raw[7] = TEST_XYL_RANGE_Y_MAX >> 8;
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(
	    TEST_ASSIGNED_MESH_OP_LIGHT_XYL_RANGE_SET, raw,
	    BT_MMDL111_XYL_RANGE_SET_LEN, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen,
	    &reply));
	ATF_CHECK_EQ(TEST_ASSIGNED_MESH_OP_LIGHT_XYL_RANGE_STATUS,
	    reply.opcode);
	ATF_CHECK_EQ(BT_MMDL111_XYL_RANGE_STATUS_LEN, reply.params_len);
	ATF_CHECK_EQ(BT_MMDL111_STATUS_SUCCESS, reply.params[0]);
	ATF_CHECK_EQ(TEST_XYL_RANGE_X_MIN, xyl.x_min);
	ATF_CHECK_EQ(TEST_XYL_RANGE_X_MAX, xyl.x_max);
	ATF_CHECK_EQ(TEST_XYL_RANGE_Y_MIN, xyl.y_min);
	ATF_CHECK_EQ(TEST_XYL_RANGE_Y_MAX, xyl.y_max);

	/* §6.3.4.12 requires each Range Max to be at least Range Min. */
	raw[0] = TEST_XYL_INVALID_X_MIN & 0xff;
	raw[1] = TEST_XYL_INVALID_X_MIN >> 8;
	raw[2] = TEST_XYL_INVALID_X_MAX & 0xff;
	raw[3] = TEST_XYL_INVALID_X_MAX >> 8;
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(
	    TEST_ASSIGNED_MESH_OP_LIGHT_XYL_RANGE_SET, raw,
	    BT_MMDL111_XYL_RANGE_SET_LEN, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_CHECK_EQ(-1, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen, &reply));
	ATF_CHECK_EQ(TEST_XYL_RANGE_X_MIN, xyl.x_min);
	ATF_CHECK_EQ(TEST_XYL_RANGE_X_MAX, xyl.x_max);
	ATF_CHECK_EQ(TEST_XYL_RANGE_Y_MIN, xyl.y_min);
	ATF_CHECK_EQ(TEST_XYL_RANGE_Y_MAX, xyl.y_max);
	/* Table 6.117 permits exactly eight parameter octets, not nine. */
	raw[8] = 0;
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(
	    TEST_ASSIGNED_MESH_OP_LIGHT_XYL_RANGE_SET, raw,
	    BT_MMDL111_XYL_RANGE_SET_LEN + 1, pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen,
	    &reply));

	memset(&set, 0, sizeof(set));
	set.lightness = TEST_XYL_UNACK_LIGHTNESS;
	set.x = TEST_XYL_UNACK_X;
	set.y = TEST_XYL_UNACK_Y;
	/* TID 4 is a non-normative transaction sentinel. */
	set.tid = 4;
	ATF_REQUIRE_EQ(0, mesh_light_xyl_cli_set(&set, 0, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(pdu, plen, &ap));
	ATF_CHECK_EQ(TEST_ASSIGNED_MESH_OP_LIGHT_XYL_SET_UNACK, ap.opcode);
	ATF_CHECK_EQ(BT_MMDL111_XYL_SET_BASE_LEN, ap.params_len);
	memset(&reply, 0xa5, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch_at(&el, 1, 1, 2, pdu, plen,
	    &reply, 3000));
	ATF_CHECK_EQ(0, reply.params_len);

	memset(raw, 0, sizeof(raw));
	raw[0] = TEST_XYL_UNACK_LIGHTNESS & 0xff;
	raw[1] = TEST_XYL_UNACK_LIGHTNESS >> 8;
	raw[2] = TEST_XYL_OUTSIDE_X & 0xff;
	raw[3] = TEST_XYL_OUTSIDE_X >> 8;
	raw[4] = TEST_XYL_UNACK_Y & 0xff;
	raw[5] = TEST_XYL_UNACK_Y >> 8;
	/* TID 5 and transition 0x01 are non-normative valid sentinels. */
	raw[6] = 5;
	raw[7] = 1;
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(
	    TEST_ASSIGNED_MESH_OP_LIGHT_XYL_SET, raw,
	    BT_MMDL111_XYL_SET_TRANSITION_LEN, pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_access_dispatch_at(&el, 1, 1, 2, pdu, plen,
	    &reply, 3100));
	/* MMDL §3.2.9.2: 0x3F selects DTT or an immediate transition. */
	raw[2] = TEST_XYL_UNACK_X & 0xff;
	raw[3] = TEST_XYL_UNACK_X >> 8;
	raw[7] = BT_MMDL111_TRANSITION_STEPS_MASK;
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(
	    TEST_ASSIGNED_MESH_OP_LIGHT_XYL_SET, raw,
	    BT_MMDL111_XYL_SET_TRANSITION_LEN, pdu, &plen));
	ATF_CHECK_EQ(0, mesh_access_dispatch_at(&el, 1, 1, 2, pdu, plen,
	    &reply, 3200));
	/* Table 6.107 permits 7 or 9 parameter octets, never 8. */
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(
	    TEST_ASSIGNED_MESH_OP_LIGHT_XYL_SET, raw,
	    BT_MMDL111_XYL_SET_BASE_LEN + 1, pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_access_dispatch_at(&el, 1, 1, 2, pdu, plen,
	    &reply, 3300));
	/* Table 6.106 defines no parameters for Light xyL Get. */
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(
	    TEST_ASSIGNED_MESH_OP_LIGHT_XYL_GET, raw, 1, pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_access_dispatch_at(&el, 1, 1, 2, pdu, plen,
	    &reply, 3400));
	models[0].user = NULL;
	ATF_REQUIRE_EQ(0, mesh_light_xyl_cli_get(
	    TEST_ASSIGNED_MESH_OP_LIGHT_XYL_GET, pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_access_dispatch_at(&el, 1, 1, 2, pdu, plen,
	    &reply, 3500));
}

ATF_TC_WITHOUT_HEAD(lc_models);
ATF_TC_BODY(lc_models, tc)
{
	struct mesh_light_lightness_srv lightness;
	struct mesh_light_lc_srv lc;
	struct mesh_light_lc_onoff_set lc_set;
	struct mesh_gen_onoff_srv onoff;
	struct mesh_gen_level_srv level;
	struct mesh_model models[2];
	struct mesh_element el;
	struct mesh_model_reply reply;
	/* 0x1234 is a non-normative valid Perceived Lightness sentinel. */
	uint8_t pdu[16], value[BT_GSS_PERCEIVED_LIGHTNESS_SIZE] = {
	    0x34, 0x12 };
	size_t plen;

	mesh_gen_onoff_srv_init(&onoff, MESH_GEN_OFF);
	mesh_gen_level_srv_init(&level, 0);
	mesh_light_lightness_srv_init(&lightness, &onoff, &level);
	/* 1000 and 500 are non-normative range-boundary sentinels. */
	lightness.last = 1000;
	mesh_light_lc_srv_init(&lc, &lightness);
	lightness.range_max = 500;
	lc.mode = 0;
	lc.light_onoff = 0;
	ATF_CHECK_EQ(-1, mesh_light_lc_set(&lc, 1, 1));
	ATF_CHECK_EQ(0, lc.mode);
	ATF_CHECK_EQ(0, lc.light_onoff);
	ATF_CHECK_EQ(0, lightness.actual);
	lightness.range_max = BT_MMDL111_LIGHTNESS_ACTUAL_MAX;
	models[0] = mesh_light_lc_srv_model(&lc);
	models[1] = mesh_light_lc_setup_srv_model(&lc);
	memset(&el, 0, sizeof(el)); el.addr = 2; el.models = models; el.n_models = 2;
	ATF_REQUIRE_EQ(0, mesh_light_lc_cli_mode_set(
	    BT_MMDL111_LIGHT_LC_MODE_ON, 1, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen, &reply));
	ATF_CHECK_EQ(TEST_MESH_OP_LIGHT_LC_MODE_STATUS, reply.opcode);
	ATF_CHECK_EQ(BT_MMDL111_LIGHT_LC_MODE_ON, lc.mode);
	memset(&lc_set, 0, sizeof(lc_set));
	lc_set.light_onoff = BT_MMDL111_LIGHT_LC_MODE_ON;
	/* TID 2 is a non-normative transaction sentinel. */
	lc_set.tid = 2;
	ATF_REQUIRE_EQ(0, mesh_light_lc_cli_light_onoff_set(&lc_set, 1, pdu,
	    &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen, &reply));
	ATF_CHECK_EQ(1000, lightness.actual);
	ATF_REQUIRE_EQ(0, mesh_light_lc_cli_property_set(
	    BT_DP_LIGHT_CONTROL_LIGHTNESS_ON_ID, value,
	    sizeof(value), 1, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen, &reply));
	ATF_CHECK_EQ(TEST_MESH_OP_LIGHT_LC_PROPERTY_STATUS, reply.opcode);
	ATF_CHECK_EQ(BT_MMDL111_LC_PROPERTY_ID_SIZE +
	    BT_GSS_PERCEIVED_LIGHTNESS_SIZE, reply.params_len);
}

ATF_TC_WITHOUT_HEAD(client_api_matrix);
ATF_TC_BODY(client_api_matrix, tc)
{
	/* Aggregate initializers below use non-normative valid state/TID sentinels. */
	struct mesh_light_lightness_cli lightness;
	struct mesh_light_lightness_set lightness_set = {
	    .lightness = 0x1234, .tid = 1
	};
	struct mesh_light_ctl_cli ctl;
	struct mesh_light_ctl_temperature_set temperature_set = {
	    .temperature = 0x1234, .delta_uv = -2, .tid = 2
	};
	struct mesh_light_ctl_default ctl_default = {
	    .lightness = 0x1111, .temperature = 0x1234, .delta_uv = -3
	};
	struct mesh_light_hsl_cli hsl;
	struct mesh_light_hsl_component_set component = {
	    .value = 0x2345, .tid = 3
	};
	struct mesh_light_hsl_triplet hsl_default = {
	    .lightness = 1, .hue = 2, .saturation = 3
	};
	struct mesh_light_hsl_range hsl_range = {
	    .hue_min = 1, .hue_max = 2,
	    .saturation_min = 3, .saturation_max = 4
	};
	struct mesh_light_xyl_cli xyl;
	struct mesh_light_xyl_triplet xyl_default = {
	    .lightness = 5, .x = 6, .y = 7
	};
	struct mesh_light_xyl_range xyl_range = {
	    .x_min = 1, .x_max = 2, .y_min = 3, .y_max = 4
	};
	struct mesh_light_lc_cli lc;
	struct mesh_light_lc_onoff_set onoff = {
	    .light_onoff = 1, .tid = 4
	};
	struct mesh_access_pdu access;
	/* Non-normative little-endian decoder sentinels 1, 2, 3, 4, 5. */
	uint8_t pdu[32], raw[9] = { 1, 0, 2, 0, 3, 0, 4, 0, 5 };
	/* Non-normative property-value sentinel. */
	uint8_t property[] = { 0xaa, 0xbb };
	size_t plen;

	/* Lightness request variants and every Status decoder shape. */
	ATF_REQUIRE_EQ(0, mesh_light_lightness_cli_linear_set(&lightness_set,
	    0, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(pdu, plen, &access));
	ATF_CHECK_EQ(TEST_ASSIGNED_MESH_OP_LIGHT_LIGHTNESS_LINEAR_SET_UNACK,
	    access.opcode);
	ATF_CHECK_EQ(BT_MMDL111_LIGHTNESS_LINEAR_SET_BASE_LEN,
	    access.params_len);
	ATF_REQUIRE_EQ(0, mesh_light_lightness_cli_default_set(0x3456, 0,
	    pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(pdu, plen, &access));
	ATF_CHECK_EQ(TEST_ASSIGNED_MESH_OP_LIGHT_LIGHTNESS_DEFAULT_SET_UNACK,
	    access.opcode);
	ATF_CHECK_EQ(BT_MMDL111_LIGHTNESS_DEFAULT_SET_LEN, access.params_len);
	ATF_CHECK_EQ(-1, mesh_light_lightness_cli_range_set(2, 1, 1, pdu,
	    &plen));
	ATF_CHECK_EQ(-1, mesh_light_lightness_cli_get(0, pdu, &plen));
	mesh_light_lightness_cli_init(&lightness);
	ATF_REQUIRE_EQ(0, mesh_light_lightness_cli_recv(&lightness,
	    TEST_ASSIGNED_MESH_OP_LIGHT_LIGHTNESS_STATUS, raw,
	    BT_MMDL111_LIGHTNESS_STATUS_TRANSITION_LEN));
	ATF_CHECK_EQ(1, lightness.actual);
	ATF_CHECK_EQ(2, lightness.target);
	ATF_CHECK_EQ(3, lightness.remaining_time);
	ATF_REQUIRE_EQ(0, mesh_light_lightness_cli_recv(&lightness,
	    TEST_ASSIGNED_MESH_OP_LIGHT_LIGHTNESS_LINEAR_STATUS, raw,
	    BT_MMDL111_LIGHTNESS_LINEAR_STATUS_TRANSITION_LEN));
	ATF_REQUIRE_EQ(0, mesh_light_lightness_cli_recv(&lightness,
	    TEST_ASSIGNED_MESH_OP_LIGHT_LIGHTNESS_LAST_STATUS, raw,
	    BT_MMDL111_LIGHTNESS_LAST_STATUS_LEN));
	ATF_REQUIRE_EQ(0, mesh_light_lightness_cli_recv(&lightness,
	    TEST_ASSIGNED_MESH_OP_LIGHT_LIGHTNESS_DEFAULT_STATUS, raw,
	    BT_MMDL111_LIGHTNESS_DEFAULT_STATUS_LEN));
	raw[0] = BT_MMDL111_STATUS_SUCCESS;
	ATF_REQUIRE_EQ(0, mesh_light_lightness_cli_recv(&lightness,
	    TEST_ASSIGNED_MESH_OP_LIGHT_LIGHTNESS_RANGE_STATUS, raw,
	    BT_MMDL111_LIGHTNESS_RANGE_STATUS_LEN));
	ATF_CHECK_EQ(-1, mesh_light_lightness_cli_recv(&lightness, 0, raw, 2));

	/* CTL temperature/default/range requests and Status forms. */
	ATF_REQUIRE_EQ(0, mesh_light_ctl_cli_temperature_set(&temperature_set,
	    0, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(pdu, plen, &access));
	ATF_CHECK_EQ(TEST_ASSIGNED_MESH_OP_LIGHT_CTL_TEMPERATURE_SET_UNACK,
	    access.opcode);
	ATF_CHECK_EQ(BT_MMDL111_CTL_TEMPERATURE_SET_BASE_LEN,
	    access.params_len);
	ATF_REQUIRE_EQ(0, mesh_light_ctl_cli_default_set(&ctl_default, 1, pdu,
	    &plen));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(pdu, plen, &access));
	ATF_CHECK_EQ(TEST_ASSIGNED_MESH_OP_LIGHT_CTL_DEFAULT_SET,
	    access.opcode);
	ATF_CHECK_EQ(BT_MMDL111_CTL_DEFAULT_SET_LEN, access.params_len);
	ATF_CHECK_EQ(-1, mesh_light_ctl_cli_default_set(NULL, 1, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_light_ctl_cli_temperature_range_set(
	    BT_MMDL111_CTL_TEMPERATURE_MIN, BT_MMDL111_CTL_TEMPERATURE_MAX,
	    0, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(pdu, plen, &access));
	ATF_CHECK_EQ(
	    TEST_ASSIGNED_MESH_OP_LIGHT_CTL_TEMPERATURE_RANGE_SET_UNACK,
	    access.opcode);
	ATF_CHECK_EQ(BT_MMDL111_CTL_TEMPERATURE_RANGE_SET_LEN,
	    access.params_len);
	ATF_CHECK_EQ(-1, mesh_light_ctl_cli_temperature_range_set(
	    BT_MMDL111_CTL_TEMPERATURE_MIN - 1,
	    BT_MMDL111_CTL_TEMPERATURE_MAX, 1, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_light_ctl_cli_get(
	    TEST_ASSIGNED_MESH_OP_LIGHT_CTL_DEFAULT_GET, pdu, &plen));
	mesh_light_ctl_cli_init(&ctl);
	ATF_REQUIRE_EQ(0, mesh_light_ctl_cli_recv(&ctl,
	    TEST_ASSIGNED_MESH_OP_LIGHT_CTL_STATUS, raw,
	    BT_MMDL111_CTL_STATUS_TRANSITION_LEN));
	ATF_REQUIRE_EQ(0, mesh_light_ctl_cli_recv(&ctl,
	    TEST_ASSIGNED_MESH_OP_LIGHT_CTL_TEMPERATURE_STATUS, raw,
	    BT_MMDL111_CTL_TEMPERATURE_STATUS_TRANSITION_LEN));
	ATF_REQUIRE_EQ(0, mesh_light_ctl_cli_recv(&ctl,
	    TEST_ASSIGNED_MESH_OP_LIGHT_CTL_DEFAULT_STATUS, raw,
	    BT_MMDL111_CTL_DEFAULT_STATUS_LEN));
	raw[0] = BT_MMDL111_STATUS_SUCCESS;
	ATF_REQUIRE_EQ(0, mesh_light_ctl_cli_recv(&ctl,
	    TEST_ASSIGNED_MESH_OP_LIGHT_CTL_TEMPERATURE_RANGE_STATUS, raw,
	    BT_MMDL111_CTL_TEMPERATURE_RANGE_STATUS_LEN));

	/* HSL component/setup encoders and all client Status families. */
	ATF_REQUIRE_EQ(0, mesh_light_hsl_cli_hue_set(&component, 0, pdu,
	    &plen));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(pdu, plen, &access));
	ATF_CHECK_EQ(TEST_ASSIGNED_MESH_OP_LIGHT_HSL_HUE_SET_UNACK,
	    access.opcode);
	ATF_CHECK_EQ(BT_MMDL111_HSL_COMPONENT_SET_BASE_LEN,
	    access.params_len);
	ATF_REQUIRE_EQ(0, mesh_light_hsl_cli_saturation_set(&component, 1, pdu,
	    &plen));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(pdu, plen, &access));
	ATF_CHECK_EQ(TEST_ASSIGNED_MESH_OP_LIGHT_HSL_SATURATION_SET,
	    access.opcode);
	ATF_REQUIRE_EQ(0, mesh_light_hsl_cli_default_set(&hsl_default, 0, pdu,
	    &plen));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(pdu, plen, &access));
	ATF_CHECK_EQ(TEST_ASSIGNED_MESH_OP_LIGHT_HSL_DEFAULT_SET_UNACK,
	    access.opcode);
	ATF_CHECK_EQ(BT_MMDL111_HSL_DEFAULT_SET_LEN, access.params_len);
	ATF_REQUIRE_EQ(0, mesh_light_hsl_cli_range_set(&hsl_range, 1, pdu,
	    &plen));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(pdu, plen, &access));
	ATF_CHECK_EQ(TEST_ASSIGNED_MESH_OP_LIGHT_HSL_RANGE_SET, access.opcode);
	ATF_CHECK_EQ(BT_MMDL111_HSL_RANGE_SET_LEN, access.params_len);
	/* Hue is circular, so a minimum greater than maximum is valid. */
	hsl_range.hue_min = 3;
	ATF_REQUIRE_EQ(0, mesh_light_hsl_cli_range_set(&hsl_range, 1, pdu,
	    &plen));
	hsl_range.saturation_min = 5;
	ATF_CHECK_EQ(-1, mesh_light_hsl_cli_range_set(&hsl_range, 1, pdu,
	    &plen));
	mesh_light_hsl_cli_init(&hsl);
	ATF_REQUIRE_EQ(0, mesh_light_hsl_cli_recv(&hsl,
	    TEST_ASSIGNED_MESH_OP_LIGHT_HSL_STATUS, raw,
	    BT_MMDL111_HSL_STATUS_TRANSITION_LEN));
	ATF_REQUIRE_EQ(0, mesh_light_hsl_cli_recv(&hsl,
	    TEST_ASSIGNED_MESH_OP_LIGHT_HSL_TARGET_STATUS, raw,
	    BT_MMDL111_HSL_TARGET_STATUS_BASE_LEN));
	ATF_REQUIRE_EQ(0, mesh_light_hsl_cli_recv(&hsl,
	    TEST_ASSIGNED_MESH_OP_LIGHT_HSL_HUE_STATUS, raw,
	    BT_MMDL111_HSL_COMPONENT_STATUS_TRANSITION_LEN));
	ATF_REQUIRE_EQ(0, mesh_light_hsl_cli_recv(&hsl,
	    TEST_ASSIGNED_MESH_OP_LIGHT_HSL_SATURATION_STATUS, raw,
	    BT_MMDL111_HSL_COMPONENT_STATUS_TRANSITION_LEN));
	ATF_REQUIRE_EQ(0, mesh_light_hsl_cli_recv(&hsl,
	    TEST_ASSIGNED_MESH_OP_LIGHT_HSL_DEFAULT_STATUS, raw,
	    BT_MMDL111_HSL_DEFAULT_STATUS_LEN));
	raw[0] = BT_MMDL111_STATUS_SUCCESS;
	ATF_REQUIRE_EQ(0, mesh_light_hsl_cli_recv(&hsl,
	    TEST_ASSIGNED_MESH_OP_LIGHT_HSL_RANGE_STATUS, raw,
	    BT_MMDL111_HSL_RANGE_STATUS_LEN));

	/* xyL setup/status variants. */
	ATF_REQUIRE_EQ(0, mesh_light_xyl_cli_default_set(&xyl_default, 0, pdu,
	    &plen));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(pdu, plen, &access));
	ATF_CHECK_EQ(TEST_ASSIGNED_MESH_OP_LIGHT_XYL_DEFAULT_SET_UNACK,
	    access.opcode);
	ATF_CHECK_EQ(BT_MMDL111_XYL_DEFAULT_SET_LEN, access.params_len);
	ATF_REQUIRE_EQ(0, mesh_light_xyl_cli_range_set(&xyl_range, 1, pdu,
	    &plen));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(pdu, plen, &access));
	ATF_CHECK_EQ(TEST_ASSIGNED_MESH_OP_LIGHT_XYL_RANGE_SET, access.opcode);
	ATF_CHECK_EQ(BT_MMDL111_XYL_RANGE_SET_LEN, access.params_len);
	xyl_range.x_min = 3;
	ATF_CHECK_EQ(-1, mesh_light_xyl_cli_range_set(&xyl_range, 1, pdu,
	    &plen));
	mesh_light_xyl_cli_init(&xyl);
	ATF_REQUIRE_EQ(0, mesh_light_xyl_cli_recv(&xyl,
	    TEST_ASSIGNED_MESH_OP_LIGHT_XYL_STATUS, raw,
	    BT_MMDL111_XYL_STATUS_TRANSITION_LEN));
	ATF_REQUIRE_EQ(0, mesh_light_xyl_cli_recv(&xyl,
	    TEST_ASSIGNED_MESH_OP_LIGHT_XYL_TARGET_STATUS, raw,
	    BT_MMDL111_XYL_TARGET_STATUS_BASE_LEN));
	ATF_REQUIRE_EQ(0, mesh_light_xyl_cli_recv(&xyl,
	    TEST_ASSIGNED_MESH_OP_LIGHT_XYL_DEFAULT_STATUS, raw,
	    BT_MMDL111_XYL_DEFAULT_STATUS_LEN));
	raw[0] = BT_MMDL111_STATUS_SUCCESS;
	ATF_REQUIRE_EQ(0, mesh_light_xyl_cli_recv(&xyl,
	    TEST_ASSIGNED_MESH_OP_LIGHT_XYL_RANGE_STATUS, raw,
	    BT_MMDL111_XYL_RANGE_STATUS_LEN));

	/* LC mode, occupancy, transition, property, and validation paths. */
	ATF_REQUIRE_EQ(0, mesh_light_lc_cli_get(
	    TEST_MESH_OP_LIGHT_LC_PROPERTY_GET,
	    BT_DP_LIGHT_CONTROL_LIGHTNESS_ON_ID, pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_light_lc_cli_get(
	    TEST_MESH_OP_LIGHT_LC_PROPERTY_GET,
	    BT_MMDL111_LC_PROPERTY_ID_PROHIBITED, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_light_lc_cli_occupancy_set(
	    BT_MMDL111_LIGHT_LC_OM_ENABLED, 0, pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_light_lc_cli_mode_set(
	    BT_MMDL111_BINARY_RFU_FIRST, 1, pdu, &plen));
	onoff.transition.has_transition = 1;
	onoff.transition.transition_time =
	    BT_MMDL111_TRANSITION_ONE_STEP_100MS;
	ATF_REQUIRE_EQ(0, mesh_light_lc_cli_light_onoff_set(&onoff, 0, pdu,
	    &plen));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(pdu, plen, &access));
	ATF_CHECK_EQ(TEST_MESH_OP_LIGHT_LC_LIGHT_ONOFF_SET_UNACK,
	    access.opcode);
	ATF_CHECK_EQ(BT_MMDL111_LC_ONOFF_SET_TRANSITION_LEN,
	    access.params_len);
	ATF_REQUIRE_EQ(0, mesh_light_lc_cli_property_set(
	    BT_DP_LIGHT_CONTROL_LIGHTNESS_ON_ID, property,
	    sizeof(property), 0, pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_light_lc_cli_property_set(
	    BT_MMDL111_LC_PROPERTY_ID_PROHIBITED, property,
	    sizeof(property), 1, pdu, &plen));
	mesh_light_lc_cli_init(&lc);
	raw[0] = BT_MMDL111_LIGHT_LC_MODE_ON;
	ATF_REQUIRE_EQ(0, mesh_light_lc_cli_recv(&lc,
	    TEST_MESH_OP_LIGHT_LC_MODE_STATUS, raw,
	    BT_MMDL111_LC_MODE_MESSAGE_PARAMS_LEN));
	ATF_REQUIRE_EQ(0, mesh_light_lc_cli_recv(&lc,
	    TEST_MESH_OP_LIGHT_LC_OM_STATUS, raw,
	    BT_MMDL111_LC_MODE_MESSAGE_PARAMS_LEN));
	raw[0] = BT_MMDL111_LIGHT_LC_MODE_OFF;
	raw[1] = BT_MMDL111_LIGHT_LC_MODE_ON;
	raw[2] = BT_MMDL111_TRANSITION_ONE_STEP_100MS;
	ATF_REQUIRE_EQ(0, mesh_light_lc_cli_recv(&lc,
	    TEST_MESH_OP_LIGHT_LC_LIGHT_ONOFF_STATUS, raw,
	    BT_MMDL111_LC_ONOFF_STATUS_TRANSITION_LEN));
	raw[0] = BT_DP_LIGHT_CONTROL_LIGHTNESS_ON_ID & 0xff;
	raw[1] = BT_DP_LIGHT_CONTROL_LIGHTNESS_ON_ID >> 8;
	raw[2] = property[0];
	ATF_REQUIRE_EQ(0, mesh_light_lc_cli_recv(&lc,
	    TEST_MESH_OP_LIGHT_LC_PROPERTY_STATUS, raw,
	    BT_MMDL111_LC_PROPERTY_ID_SIZE + 1));

	/* Client decoders reject every malformed status shape. */
	ATF_CHECK_EQ(-1, mesh_light_lightness_cli_recv(NULL,
	    TEST_ASSIGNED_MESH_OP_LIGHT_LIGHTNESS_STATUS, raw,
	    BT_MMDL111_LIGHTNESS_STATUS_BASE_LEN));
	ATF_CHECK_EQ(-1, mesh_light_lightness_cli_recv(&lightness,
	    TEST_ASSIGNED_MESH_OP_LIGHT_LIGHTNESS_STATUS, NULL,
	    BT_MMDL111_LIGHTNESS_STATUS_BASE_LEN));
	ATF_CHECK_EQ(-1, mesh_light_lightness_cli_recv(&lightness,
	    TEST_ASSIGNED_MESH_OP_LIGHT_LIGHTNESS_STATUS, raw,
	    BT_MMDL111_LIGHTNESS_STATUS_BASE_LEN + 1));
	ATF_CHECK_EQ(-1, mesh_light_lightness_cli_recv(&lightness,
	    TEST_ASSIGNED_MESH_OP_LIGHT_LIGHTNESS_LINEAR_STATUS, raw,
	    BT_MMDL111_LIGHTNESS_LINEAR_STATUS_TRANSITION_LEN - 1));
	ATF_CHECK_EQ(-1, mesh_light_lightness_cli_recv(&lightness,
	    TEST_ASSIGNED_MESH_OP_LIGHT_LIGHTNESS_LAST_STATUS, raw,
	    BT_MMDL111_LIGHTNESS_LAST_STATUS_LEN - 1));
	ATF_CHECK_EQ(-1, mesh_light_lightness_cli_recv(&lightness,
	    TEST_ASSIGNED_MESH_OP_LIGHT_LIGHTNESS_DEFAULT_STATUS, raw,
	    BT_MMDL111_LIGHTNESS_DEFAULT_STATUS_LEN - 1));
	raw[0] = BT_MMDL111_STATUS_RFU_FIRST;
	ATF_CHECK_EQ(-1, mesh_light_lightness_cli_recv(&lightness,
	    TEST_ASSIGNED_MESH_OP_LIGHT_LIGHTNESS_RANGE_STATUS, raw,
	    BT_MMDL111_LIGHTNESS_RANGE_STATUS_LEN));
	raw[0] = BT_MMDL111_LIGHT_LC_MODE_ON;
	ATF_REQUIRE_EQ(0, mesh_light_lc_cli_recv(&lc,
	    TEST_MESH_OP_LIGHT_LC_LIGHT_ONOFF_STATUS, raw,
	    BT_MMDL111_LC_ONOFF_STATUS_BASE_LEN));
	ATF_CHECK_EQ(0, lc.has_target);
	ATF_CHECK_EQ(-1, mesh_light_lc_cli_recv(&lc, 0, raw, 1));
	ATF_CHECK_EQ(-1, mesh_light_lc_cli_recv(NULL,
	    TEST_MESH_OP_LIGHT_LC_MODE_STATUS, raw,
	    BT_MMDL111_LC_MODE_MESSAGE_PARAMS_LEN));
	raw[0] = BT_MMDL111_BINARY_RFU_FIRST;
	ATF_CHECK_EQ(-1, mesh_light_lc_cli_recv(&lc,
	    TEST_MESH_OP_LIGHT_LC_MODE_STATUS, raw,
	    BT_MMDL111_LC_MODE_MESSAGE_PARAMS_LEN));
	raw[0] = BT_MMDL111_LC_PROPERTY_ID_PROHIBITED & 0xff;
	raw[1] = BT_MMDL111_LC_PROPERTY_ID_PROHIBITED >> 8;
	ATF_CHECK_EQ(-1, mesh_light_lc_cli_recv(&lc,
	    TEST_MESH_OP_LIGHT_LC_PROPERTY_STATUS, raw,
	    BT_MMDL111_LC_PROPERTY_ID_SIZE));
}

ATF_TC_WITHOUT_HEAD(client_guard_completion);
ATF_TC_BODY(client_guard_completion, tc)
{
	struct mesh_light_ctl_set ctl;
	struct mesh_light_ctl_temperature_set temp;
	struct mesh_light_ctl_cli ctl_cli;
	struct mesh_light_hsl_set hsl;
	struct mesh_light_hsl_component_set component;
	struct mesh_light_hsl_cli hsl_cli;
	struct mesh_light_xyl_set xyl;
	struct mesh_light_xyl_cli xyl_cli;
	struct mesh_light_lc_onoff_set lc_onoff;
	struct mesh_light_lc_cli lc_cli;
	struct mesh_access_pdu ap;
	uint8_t pdu[32], raw[9] = { 0 };
	size_t plen;

	ATF_CHECK_EQ(-1, mesh_light_lightness_cli_actual_set(NULL, 1, pdu,
	    &plen));

	mesh_light_ctl_srv_init(NULL, NULL);
	ATF_CHECK_EQ(-1, mesh_light_ctl_cli_get(UINT32_MAX, pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_light_ctl_cli_set(NULL, 1, pdu, &plen));
	memset(&ctl, 0, sizeof(ctl));
	ctl.temperature = BT_MMDL111_CTL_TEMPERATURE_MIN;
	ctl.transition.has_transition = 1;
	ctl.transition.transition_time = BT_MMDL111_TRANSITION_STEPS_MASK;
	ATF_CHECK_EQ(0, mesh_light_ctl_cli_set(&ctl, 1, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(pdu, plen, &ap));
	ATF_CHECK_EQ(TEST_ASSIGNED_MESH_OP_LIGHT_CTL_SET, ap.opcode);
	ATF_CHECK_EQ(BT_MMDL111_CTL_SET_TRANSITION_LEN, ap.params_len);
	ATF_CHECK_EQ(BT_MMDL111_TRANSITION_STEPS_MASK, ap.params[7]);
	ATF_CHECK_EQ(-1, mesh_light_ctl_cli_temperature_set(NULL, 1, pdu,
	    &plen));
	memset(&temp, 0, sizeof(temp));
	temp.temperature = BT_MMDL111_CTL_TEMPERATURE_MIN;
	temp.transition.has_transition = 1;
	temp.transition.transition_time = BT_MMDL111_TRANSITION_STEPS_MASK;
	ATF_CHECK_EQ(0, mesh_light_ctl_cli_temperature_set(&temp, 1, pdu,
	    &plen));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(pdu, plen, &ap));
	ATF_CHECK_EQ(TEST_ASSIGNED_MESH_OP_LIGHT_CTL_TEMPERATURE_SET,
	    ap.opcode);
	ATF_CHECK_EQ(BT_MMDL111_CTL_TEMPERATURE_SET_TRANSITION_LEN,
	    ap.params_len);
	ATF_CHECK_EQ(BT_MMDL111_TRANSITION_STEPS_MASK, ap.params[5]);
	ATF_CHECK_EQ(-1, mesh_light_ctl_cli_recv(NULL, 0, raw, 0));
	raw[0] = BT_MMDL111_STATUS_RFU_FIRST;
	ATF_CHECK_EQ(-1, mesh_light_ctl_cli_recv(&ctl_cli,
	    TEST_ASSIGNED_MESH_OP_LIGHT_CTL_TEMPERATURE_RANGE_STATUS, raw,
	    BT_MMDL111_CTL_TEMPERATURE_RANGE_STATUS_LEN));

	ATF_CHECK_EQ(-1, mesh_light_hsl_cli_get(UINT32_MAX, pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_light_hsl_cli_set(NULL, 1, pdu, &plen));
	memset(&hsl, 0, sizeof(hsl));
	hsl.transition.has_transition = 1;
	hsl.transition.transition_time = BT_MMDL111_TRANSITION_STEPS_MASK;
	ATF_CHECK_EQ(0, mesh_light_hsl_cli_set(&hsl, 1, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(pdu, plen, &ap));
	ATF_CHECK_EQ(TEST_ASSIGNED_MESH_OP_LIGHT_HSL_SET, ap.opcode);
	ATF_CHECK_EQ(BT_MMDL111_HSL_SET_TRANSITION_LEN, ap.params_len);
	ATF_CHECK_EQ(BT_MMDL111_TRANSITION_STEPS_MASK, ap.params[7]);
	ATF_CHECK_EQ(-1, mesh_light_hsl_cli_hue_set(NULL, 1, pdu, &plen));
	memset(&component, 0, sizeof(component));
	component.transition.has_transition = 1;
	component.transition.transition_time = BT_MMDL111_TRANSITION_STEPS_MASK;
	ATF_CHECK_EQ(0, mesh_light_hsl_cli_hue_set(&component, 1, pdu,
	    &plen));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(pdu, plen, &ap));
	ATF_CHECK_EQ(TEST_ASSIGNED_MESH_OP_LIGHT_HSL_HUE_SET, ap.opcode);
	ATF_CHECK_EQ(BT_MMDL111_HSL_COMPONENT_SET_TRANSITION_LEN,
	    ap.params_len);
	ATF_CHECK_EQ(BT_MMDL111_TRANSITION_STEPS_MASK, ap.params[3]);
	ATF_CHECK_EQ(-1, mesh_light_hsl_cli_default_set(NULL, 1, pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_light_hsl_cli_recv(NULL, 0, raw, 0));
	(void)hsl_cli;

	ATF_CHECK_EQ(-1, mesh_light_xyl_cli_get(UINT32_MAX, pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_light_xyl_cli_set(NULL, 1, pdu, &plen));
	memset(&xyl, 0, sizeof(xyl));
	xyl.transition.has_transition = 1;
	xyl.transition.transition_time = BT_MMDL111_TRANSITION_STEPS_MASK;
	ATF_CHECK_EQ(0, mesh_light_xyl_cli_set(&xyl, 1, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(pdu, plen, &ap));
	ATF_CHECK_EQ(TEST_ASSIGNED_MESH_OP_LIGHT_XYL_SET, ap.opcode);
	ATF_CHECK_EQ(BT_MMDL111_XYL_SET_TRANSITION_LEN, ap.params_len);
	ATF_CHECK_EQ(BT_MMDL111_TRANSITION_STEPS_MASK, ap.params[7]);
	ATF_CHECK_EQ(-1, mesh_light_xyl_cli_recv(NULL, 0, raw, 0));
	ATF_CHECK_EQ(-1, mesh_light_xyl_cli_default_set(NULL, 1, pdu, &plen));
	(void)xyl_cli;

	mesh_light_lc_srv_init(NULL, NULL);
	ATF_CHECK_EQ(-1, mesh_light_lc_set(NULL, 0, 0));
	ATF_CHECK_EQ(-1, mesh_light_lc_cli_mode_set(
	    BT_MMDL111_BINARY_RFU_FIRST, 1, pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_light_lc_cli_occupancy_set(
	    BT_MMDL111_BINARY_RFU_FIRST, 1, pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_light_lc_cli_light_onoff_set(NULL, 1, pdu,
	    &plen));
	memset(&lc_onoff, 0, sizeof(lc_onoff));
	lc_onoff.light_onoff = BT_MMDL111_BINARY_RFU_FIRST;
	ATF_CHECK_EQ(-1, mesh_light_lc_cli_light_onoff_set(&lc_onoff, 1, pdu,
	    &plen));
	ATF_CHECK_EQ(-1, mesh_light_lc_cli_property_set(0, NULL, 0, 1, pdu,
	    &plen));
	raw[0] = BT_MMDL111_LIGHT_LC_MODE_ON;
	raw[1] = BT_MMDL111_LIGHT_LC_MODE_ON;
	raw[2] = BT_MMDL111_TRANSITION_STEPS_MASK;
	/* MMDL 1.1.1 §3.2.10.2: 0x3F means unknown Remaining Time. */
	ATF_CHECK_EQ(0, mesh_light_lc_cli_recv(&lc_cli,
	    TEST_MESH_OP_LIGHT_LC_LIGHT_ONOFF_STATUS, raw,
	    BT_MMDL111_LC_LIGHT_ONOFF_STATUS_TRANSITION_LEN));
	ATF_CHECK_EQ(1, lc_cli.has_target);
	ATF_CHECK_EQ(BT_MMDL111_TRANSITION_STEPS_MASK,
	    lc_cli.remaining_time);
}

ATF_TC_WITHOUT_HEAD(lightness_getters_and_unacknowledged_sets);
ATF_TC_BODY(lightness_getters_and_unacknowledged_sets, tc)
{
	static const struct {
		uint32_t request;
		uint32_t response;
		size_t response_len;
	} getters[] = {
		{ TEST_ASSIGNED_MESH_OP_LIGHT_LIGHTNESS_LINEAR_GET,
		    TEST_ASSIGNED_MESH_OP_LIGHT_LIGHTNESS_LINEAR_STATUS,
		    BT_MMDL111_LIGHTNESS_LINEAR_STATUS_BASE_LEN },
		{ TEST_ASSIGNED_MESH_OP_LIGHT_LIGHTNESS_LAST_GET,
		    TEST_ASSIGNED_MESH_OP_LIGHT_LIGHTNESS_LAST_STATUS,
		    BT_MMDL111_LIGHTNESS_LAST_STATUS_LEN },
		{ TEST_ASSIGNED_MESH_OP_LIGHT_LIGHTNESS_DEFAULT_GET,
		    TEST_ASSIGNED_MESH_OP_LIGHT_LIGHTNESS_DEFAULT_STATUS,
		    BT_MMDL111_LIGHTNESS_DEFAULT_STATUS_LEN },
		{ TEST_ASSIGNED_MESH_OP_LIGHT_LIGHTNESS_RANGE_GET,
		    TEST_ASSIGNED_MESH_OP_LIGHT_LIGHTNESS_RANGE_STATUS,
		    BT_MMDL111_LIGHTNESS_RANGE_STATUS_LEN },
	};
	struct mesh_light_lightness_srv server;
	struct mesh_light_lightness_set set;
	struct mesh_gen_onoff_srv onoff;
	struct mesh_gen_level_srv level;
	struct mesh_model models[2];
	struct mesh_element element;
	struct mesh_model_reply reply;
	struct mesh_access_pdu ap;
	uint8_t pdu[16], raw[5];
	size_t i, plen;
	enum {
		/* Non-normative valid state, range, and transaction sentinels. */
		TEST_LIGHTNESS_LINEAR = 100,
		TEST_LIGHTNESS_LAST = 123,
		TEST_LIGHTNESS_DEFAULT = 456,
		TEST_LIGHTNESS_DEFAULT_UNACK = 789,
		TEST_LIGHTNESS_DEFAULT_ACK = 800,
		TEST_LIGHTNESS_RANGE_MIN = 2,
		TEST_LIGHTNESS_RANGE_MAX = 900,
		TEST_LIGHTNESS_INVALID_BELOW_RANGE = 1,
		TEST_LIGHTNESS_VALID_IN_RANGE = 100,
		TEST_LIGHTNESS_TID_INITIAL = 9,
		TEST_LIGHTNESS_TID_INVALID_TRANSITION = 20,
		TEST_LIGHTNESS_TID_INVALID_BASE = 21,
		TEST_LIGHTNESS_TID_DTT = 22
	};

	mesh_gen_onoff_srv_init(&onoff, MESH_GEN_OFF);
	mesh_gen_level_srv_init(&level, 0);
	mesh_light_lightness_srv_init(&server, &onoff, &level);
	/* §6.1.2.2 defines Linear = Actual² / 65535. */
	ATF_CHECK_EQ(0, mesh_light_lightness_linear(0));
	ATF_CHECK_EQ(BT_MMDL111_LIGHTNESS_ACTUAL_MAX,
	    mesh_light_lightness_linear(BT_MMDL111_LIGHTNESS_ACTUAL_MAX));
	server.last = TEST_LIGHTNESS_LAST;
	server.default_lightness = TEST_LIGHTNESS_DEFAULT;
	server.range_min = BT_MMDL111_GENERIC_ONOFF_ON;
	server.range_max = BT_MMDL111_LIGHTNESS_ACTUAL_MAX;
	models[0] = mesh_light_lightness_srv_model(&server);
	models[1] = mesh_light_lightness_setup_srv_model(&server);
	memset(&element, 0, sizeof(element));
	element.addr = 2;
	element.models = models;
	element.n_models = 2;

	for (i = 0; i < sizeof(getters) / sizeof(getters[0]); i++) {
		ATF_REQUIRE_EQ(0, mesh_light_lightness_cli_get(
		    getters[i].request, pdu, &plen));
		memset(&reply, 0, sizeof(reply));
		ATF_REQUIRE_EQ(0, mesh_access_dispatch(&element, 1, 1, 2,
		    pdu, plen, &reply));
		ATF_CHECK_EQ(getters[i].response, reply.opcode);
		ATF_CHECK_EQ(getters[i].response_len, reply.params_len);
	}

	ATF_REQUIRE_EQ(0, mesh_light_lightness_cli_default_set(
	    TEST_LIGHTNESS_DEFAULT_UNACK, 0, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(pdu, plen, &ap));
	ATF_CHECK_EQ(TEST_ASSIGNED_MESH_OP_LIGHT_LIGHTNESS_DEFAULT_SET_UNACK,
	    ap.opcode);
	ATF_CHECK_EQ(BT_MMDL111_LIGHTNESS_DEFAULT_SET_LEN, ap.params_len);
	memset(&reply, 0xff, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&element, 1, 1, 2, pdu, plen,
	    &reply));
	ATF_CHECK_EQ(TEST_LIGHTNESS_DEFAULT_UNACK, server.default_lightness);
	ATF_CHECK_EQ(0, reply.have_reply);

	memset(&set, 0, sizeof(set));
	set.lightness = TEST_LIGHTNESS_LINEAR;
	set.tid = TEST_LIGHTNESS_TID_INITIAL;
	ATF_REQUIRE_EQ(0, mesh_light_lightness_cli_linear_set(&set, 0, pdu,
	    &plen));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(pdu, plen, &ap));
	ATF_CHECK_EQ(TEST_ASSIGNED_MESH_OP_LIGHT_LIGHTNESS_LINEAR_SET_UNACK,
	    ap.opcode);
	ATF_CHECK_EQ(BT_MMDL111_LIGHTNESS_LINEAR_SET_BASE_LEN,
	    ap.params_len);
	memset(&reply, 0xff, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&element, 1, 1, 2, pdu, plen,
	    &reply));
	ATF_CHECK(server.actual > 0);
	ATF_CHECK_EQ(0, reply.have_reply);

	/* Cover acknowledged setup and the linear target-status encoding. */
	ATF_REQUIRE_EQ(0, mesh_light_lightness_cli_default_set(
	    TEST_LIGHTNESS_DEFAULT_ACK, 1, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&element, 1, 1, 2, pdu, plen,
	    &reply));
	ATF_CHECK_EQ(TEST_ASSIGNED_MESH_OP_LIGHT_LIGHTNESS_DEFAULT_STATUS,
	    reply.opcode);
	ATF_CHECK_EQ(BT_MMDL111_LIGHTNESS_DEFAULT_STATUS_LEN,
	    reply.params_len);
	ATF_CHECK_EQ(TEST_LIGHTNESS_DEFAULT_ACK, server.default_lightness);
	ATF_REQUIRE_EQ(0, mesh_light_lightness_cli_range_set(
	    TEST_LIGHTNESS_RANGE_MIN, TEST_LIGHTNESS_RANGE_MAX, 0, pdu,
	    &plen));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(pdu, plen, &ap));
	ATF_CHECK_EQ(TEST_ASSIGNED_MESH_OP_LIGHT_LIGHTNESS_RANGE_SET_UNACK,
	    ap.opcode);
	ATF_CHECK_EQ(BT_MMDL111_LIGHTNESS_RANGE_SET_LEN, ap.params_len);
	memset(&reply, 0xff, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&element, 1, 1, 2, pdu, plen,
	    &reply));
	ATF_CHECK_EQ(0, reply.have_reply);

	set.lightness = TEST_LIGHTNESS_INVALID_BELOW_RANGE;
	set.tid++;
	set.transition.has_transition = 1;
	/* 0x01 is one 100 ms step (§3.1.10, Table 3.33). */
	set.transition.transition_time = 1;
	set.transition.delay = 0;
	ATF_REQUIRE_EQ(0, mesh_light_lightness_cli_linear_set(&set, 1, pdu,
	    &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 100));
	ATF_CHECK_EQ(TEST_ASSIGNED_MESH_OP_LIGHT_LIGHTNESS_LINEAR_STATUS,
	    reply.opcode);
	ATF_CHECK_EQ(BT_MMDL111_LIGHTNESS_LINEAR_STATUS_TRANSITION_LEN,
	    reply.params_len);

	for (i = 0; i < sizeof(getters) / sizeof(getters[0]); i++) {
		raw[0] = 0;
		ATF_REQUIRE_EQ(0, mesh_access_pdu_build(getters[i].request, raw,
		    1, pdu, &plen));
		ATF_CHECK_EQ(-1, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
		    plen, &reply, 1000));
	}
	memset(raw, 0, sizeof(raw));
	raw[0] = TEST_LIGHTNESS_INVALID_BELOW_RANGE & 0xff;
	raw[1] = TEST_LIGHTNESS_INVALID_BELOW_RANGE >> 8;
	raw[2] = TEST_LIGHTNESS_TID_INVALID_TRANSITION;
	raw[3] = 1; /* One 100 ms transition step (Table 3.33). */
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(
	    TEST_ASSIGNED_MESH_OP_LIGHT_LIGHTNESS_SET, raw,
	    BT_MMDL111_LIGHTNESS_SET_TRANSITION_LEN, pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 1100));
	raw[2] = TEST_LIGHTNESS_TID_INVALID_BASE;
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(
	    TEST_ASSIGNED_MESH_OP_LIGHT_LIGHTNESS_SET, raw,
	    BT_MMDL111_LIGHTNESS_SET_BASE_LEN, pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 1200));
	/* MMDL §3.2.9.2: 0x3F selects DTT or an immediate transition. */
	raw[0] = TEST_LIGHTNESS_VALID_IN_RANGE & 0xff;
	raw[1] = TEST_LIGHTNESS_VALID_IN_RANGE >> 8;
	/* A fresh TID ensures this exercises processing, not deduplication. */
	raw[2] = TEST_LIGHTNESS_TID_DTT;
	raw[3] = BT_MMDL111_TRANSITION_STEPS_MASK;
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(
	    TEST_ASSIGNED_MESH_OP_LIGHT_LIGHTNESS_SET, raw,
	    BT_MMDL111_LIGHTNESS_SET_TRANSITION_LEN, pdu, &plen));
	ATF_CHECK_EQ(0, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 1300));
	ATF_CHECK_EQ(TEST_LIGHTNESS_VALID_IN_RANGE, server.actual);
	/* Tables 6.51/6.53 permit 3 or 5 parameter octets, never 4. */
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(
	    TEST_ASSIGNED_MESH_OP_LIGHT_LIGHTNESS_SET, raw,
	    BT_MMDL111_LIGHTNESS_SET_BASE_LEN + 1, pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 1400));
	models[0].user = NULL;
	ATF_REQUIRE_EQ(0, mesh_light_lightness_cli_get(
	    TEST_ASSIGNED_MESH_OP_LIGHT_LIGHTNESS_GET, pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 1500));
}

ATF_TC_WITHOUT_HEAD(ctl_hsl_xyl_setup_dispatch_matrix);
ATF_TC_BODY(ctl_hsl_xyl_setup_dispatch_matrix, tc)
{
	struct mesh_gen_onoff_srv onoff;
	struct mesh_gen_level_srv level;
	struct mesh_light_lightness_srv lightness;
	struct mesh_light_ctl_srv ctl;
	struct mesh_light_ctl_default ctl_default;
	struct mesh_light_hsl_srv hsl;
	struct mesh_light_hsl_triplet hsl_default;
	struct mesh_light_hsl_range hsl_range;
	struct mesh_light_xyl_srv xyl;
	struct mesh_light_xyl_triplet xyl_default;
	struct mesh_light_xyl_range xyl_range;
	struct mesh_model models[4];
	struct mesh_element element;
	struct mesh_model_reply reply;
	uint8_t pdu[32];
	size_t plen;
	enum {
		/* Non-normative valid default and ordered-range sentinels. */
		TEST_SETUP_LIGHTNESS = 100,
		TEST_SETUP_CTL_TEMPERATURE = 3000,
		TEST_SETUP_CTL_DELTA_UV = -2,
		TEST_SETUP_FIRST_COMPONENT = 200,
		TEST_SETUP_SECOND_COMPONENT = 300,
		TEST_SETUP_FIRST_RANGE_MIN = 1,
		TEST_SETUP_FIRST_RANGE_MAX = 1000,
		TEST_SETUP_SECOND_RANGE_MIN = 2,
		TEST_SETUP_SECOND_RANGE_MAX = 2000
	};

#define DISPATCH_REPLY(expected_opcode, expected_len) do {                   \
	memset(&reply, 0, sizeof(reply));                                      \
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&element, 1, 1, 2, pdu, plen,  \
	    &reply));                                                           \
	ATF_CHECK_EQ((expected_opcode), reply.opcode);                          \
	ATF_CHECK_EQ((expected_len), reply.params_len);                         \
} while (0)
#define DISPATCH_NO_REPLY() do {                                             \
	memset(&reply, 0xa5, sizeof(reply));                                   \
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&element, 1, 1, 2, pdu, plen,  \
	    &reply));                                                           \
	ATF_CHECK_EQ(0, reply.have_reply);                                      \
} while (0)

	ctl_default.lightness = TEST_SETUP_LIGHTNESS;
	ctl_default.temperature = TEST_SETUP_CTL_TEMPERATURE;
	ctl_default.delta_uv = TEST_SETUP_CTL_DELTA_UV;
	hsl_default.lightness = TEST_SETUP_LIGHTNESS;
	hsl_default.hue = TEST_SETUP_FIRST_COMPONENT;
	hsl_default.saturation = TEST_SETUP_SECOND_COMPONENT;
	hsl_range.hue_min = TEST_SETUP_FIRST_RANGE_MIN;
	hsl_range.hue_max = TEST_SETUP_FIRST_RANGE_MAX;
	hsl_range.saturation_min = TEST_SETUP_SECOND_RANGE_MIN;
	hsl_range.saturation_max = TEST_SETUP_SECOND_RANGE_MAX;
	xyl_default.lightness = TEST_SETUP_LIGHTNESS;
	xyl_default.x = TEST_SETUP_FIRST_COMPONENT;
	xyl_default.y = TEST_SETUP_SECOND_COMPONENT;
	xyl_range.x_min = TEST_SETUP_FIRST_RANGE_MIN;
	xyl_range.x_max = TEST_SETUP_FIRST_RANGE_MAX;
	xyl_range.y_min = TEST_SETUP_SECOND_RANGE_MIN;
	xyl_range.y_max = TEST_SETUP_SECOND_RANGE_MAX;

	mesh_gen_onoff_srv_init(&onoff, MESH_GEN_OFF);
	mesh_gen_level_srv_init(&level, 0);
	mesh_light_lightness_srv_init(&lightness, &onoff, &level);
	mesh_light_ctl_srv_init(&ctl, &lightness);
	models[0] = mesh_light_ctl_srv_model(&ctl);
	models[1] = mesh_light_ctl_setup_srv_model(&ctl);
	models[2] = mesh_light_ctl_temp_srv_model(&ctl);
	memset(&element, 0, sizeof(element));
	element.addr = 2; element.models = models; element.n_models = 3;
	ATF_REQUIRE_EQ(0, mesh_light_ctl_cli_get(
	    TEST_ASSIGNED_MESH_OP_LIGHT_CTL_GET, pdu, &plen));
	DISPATCH_REPLY(TEST_ASSIGNED_MESH_OP_LIGHT_CTL_STATUS,
	    BT_MMDL111_CTL_STATUS_BASE_LEN);
	ATF_REQUIRE_EQ(0, mesh_light_ctl_cli_get(
	    TEST_ASSIGNED_MESH_OP_LIGHT_CTL_DEFAULT_GET, pdu, &plen));
	DISPATCH_REPLY(TEST_ASSIGNED_MESH_OP_LIGHT_CTL_DEFAULT_STATUS,
	    BT_MMDL111_CTL_DEFAULT_STATUS_LEN);
	ATF_REQUIRE_EQ(0, mesh_light_ctl_cli_get(
	    TEST_ASSIGNED_MESH_OP_LIGHT_CTL_TEMPERATURE_RANGE_GET, pdu,
	    &plen));
	DISPATCH_REPLY(TEST_ASSIGNED_MESH_OP_LIGHT_CTL_TEMPERATURE_RANGE_STATUS,
	    BT_MMDL111_CTL_TEMPERATURE_RANGE_STATUS_LEN);
	ATF_REQUIRE_EQ(0, mesh_light_ctl_cli_default_set(&ctl_default, 1, pdu,
	    &plen));
	DISPATCH_REPLY(TEST_ASSIGNED_MESH_OP_LIGHT_CTL_DEFAULT_STATUS,
	    BT_MMDL111_CTL_DEFAULT_STATUS_LEN);
	ATF_REQUIRE_EQ(0, mesh_light_ctl_cli_temperature_range_set(
	    BT_MMDL111_CTL_TEMPERATURE_MIN, BT_MMDL111_CTL_TEMPERATURE_MAX,
	    1, pdu, &plen));
	DISPATCH_REPLY(TEST_ASSIGNED_MESH_OP_LIGHT_CTL_TEMPERATURE_RANGE_STATUS,
	    BT_MMDL111_CTL_TEMPERATURE_RANGE_STATUS_LEN);
	ATF_REQUIRE_EQ(0, mesh_light_ctl_cli_default_set(&ctl_default, 0, pdu,
	    &plen));
	DISPATCH_NO_REPLY();
	ATF_REQUIRE_EQ(0, mesh_light_ctl_cli_temperature_range_set(
	    BT_MMDL111_CTL_TEMPERATURE_MIN, BT_MMDL111_CTL_TEMPERATURE_MAX,
	    0, pdu, &plen));
	DISPATCH_NO_REPLY();

	mesh_light_hsl_srv_init(&hsl, &lightness);
	models[0] = mesh_light_hsl_srv_model(&hsl);
	models[1] = mesh_light_hsl_setup_srv_model(&hsl);
	models[2] = mesh_light_hsl_hue_srv_model(&hsl);
	models[3] = mesh_light_hsl_sat_srv_model(&hsl);
	element.models = models; element.n_models = 4;
	ATF_REQUIRE_EQ(0, mesh_light_hsl_cli_get(
	    TEST_ASSIGNED_MESH_OP_LIGHT_HSL_GET, pdu, &plen));
	DISPATCH_REPLY(TEST_ASSIGNED_MESH_OP_LIGHT_HSL_STATUS,
	    BT_MMDL111_HSL_STATUS_BASE_LEN);
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(
	    TEST_ASSIGNED_MESH_OP_LIGHT_HSL_DEFAULT_GET, NULL, 0, pdu,
	    &plen));
	DISPATCH_REPLY(TEST_ASSIGNED_MESH_OP_LIGHT_HSL_DEFAULT_STATUS,
	    BT_MMDL111_HSL_DEFAULT_STATUS_LEN);
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(
	    TEST_ASSIGNED_MESH_OP_LIGHT_HSL_RANGE_GET, NULL, 0, pdu, &plen));
	DISPATCH_REPLY(TEST_ASSIGNED_MESH_OP_LIGHT_HSL_RANGE_STATUS,
	    BT_MMDL111_HSL_RANGE_STATUS_LEN);
	ATF_REQUIRE_EQ(0, mesh_light_hsl_cli_default_set(&hsl_default, 1, pdu,
	    &plen));
	DISPATCH_REPLY(TEST_ASSIGNED_MESH_OP_LIGHT_HSL_DEFAULT_STATUS,
	    BT_MMDL111_HSL_DEFAULT_STATUS_LEN);
	ATF_REQUIRE_EQ(0, mesh_light_hsl_cli_range_set(&hsl_range, 1, pdu,
	    &plen));
	DISPATCH_REPLY(TEST_ASSIGNED_MESH_OP_LIGHT_HSL_RANGE_STATUS,
	    BT_MMDL111_HSL_RANGE_STATUS_LEN);
	ATF_REQUIRE_EQ(0, mesh_light_hsl_cli_default_set(&hsl_default, 0, pdu,
	    &plen));
	DISPATCH_NO_REPLY();
	ATF_REQUIRE_EQ(0, mesh_light_hsl_cli_range_set(&hsl_range, 0, pdu,
	    &plen));
	DISPATCH_NO_REPLY();

	mesh_light_xyl_srv_init(&xyl, &lightness);
	models[0] = mesh_light_xyl_srv_model(&xyl);
	models[1] = mesh_light_xyl_setup_srv_model(&xyl);
	element.models = models; element.n_models = 2;
	ATF_REQUIRE_EQ(0, mesh_light_xyl_cli_get(
	    TEST_ASSIGNED_MESH_OP_LIGHT_XYL_GET, pdu, &plen));
	DISPATCH_REPLY(TEST_ASSIGNED_MESH_OP_LIGHT_XYL_STATUS,
	    BT_MMDL111_XYL_STATUS_BASE_LEN);
	ATF_REQUIRE_EQ(0, mesh_light_xyl_cli_get(
	    TEST_ASSIGNED_MESH_OP_LIGHT_XYL_DEFAULT_GET, pdu, &plen));
	DISPATCH_REPLY(TEST_ASSIGNED_MESH_OP_LIGHT_XYL_DEFAULT_STATUS,
	    BT_MMDL111_XYL_DEFAULT_STATUS_LEN);
	ATF_REQUIRE_EQ(0, mesh_light_xyl_cli_get(
	    TEST_ASSIGNED_MESH_OP_LIGHT_XYL_RANGE_GET, pdu, &plen));
	DISPATCH_REPLY(TEST_ASSIGNED_MESH_OP_LIGHT_XYL_RANGE_STATUS,
	    BT_MMDL111_XYL_RANGE_STATUS_LEN);
	ATF_REQUIRE_EQ(0, mesh_light_xyl_cli_default_set(&xyl_default, 1, pdu,
	    &plen));
	DISPATCH_REPLY(TEST_ASSIGNED_MESH_OP_LIGHT_XYL_DEFAULT_STATUS,
	    BT_MMDL111_XYL_DEFAULT_STATUS_LEN);
	ATF_REQUIRE_EQ(0, mesh_light_xyl_cli_range_set(&xyl_range, 1, pdu,
	    &plen));
	DISPATCH_REPLY(TEST_ASSIGNED_MESH_OP_LIGHT_XYL_RANGE_STATUS,
	    BT_MMDL111_XYL_RANGE_STATUS_LEN);
	ATF_REQUIRE_EQ(0, mesh_light_xyl_cli_default_set(&xyl_default, 0, pdu,
	    &plen));
	DISPATCH_NO_REPLY();
	ATF_REQUIRE_EQ(0, mesh_light_xyl_cli_range_set(&xyl_range, 0, pdu,
	    &plen));
	DISPATCH_NO_REPLY();
#undef DISPATCH_NO_REPLY
#undef DISPATCH_REPLY
}

ATF_TC_WITHOUT_HEAD(ctl_temperature_transition_matrix);
ATF_TC_BODY(ctl_temperature_transition_matrix, tc)
{
	struct mesh_gen_onoff_srv onoff;
	struct mesh_gen_level_srv level;
	struct mesh_light_lightness_srv lightness;
	struct mesh_light_ctl_srv ctl;
	struct mesh_light_ctl_temperature_set temp_set;
	struct mesh_light_ctl_set ctl_set;
	struct mesh_model models[2];
	struct mesh_element element;
	struct mesh_model_reply reply;
	uint8_t pdu[32], raw[9];
	size_t plen;
	enum {
		/* Non-normative valid state and transaction sentinels. */
		TEST_CTL_TARGET_TEMPERATURE = 4000,
		TEST_CTL_TARGET_DELTA_UV = -100,
		TEST_CTL_IMMEDIATE_TEMPERATURE = 3500,
		TEST_CTL_IMMEDIATE_DELTA_UV = 25,
		TEST_CTL_ACK_TEMPERATURE = 3600,
		TEST_CTL_ACK_DELTA_UV = 30,
		TEST_CTL_TARGET_LIGHTNESS = 2000,
		TEST_CTL_FULL_TARGET_TEMPERATURE = 4500,
		TEST_CTL_FULL_TARGET_DELTA_UV = -50,
		TEST_CTL_TID_TRANSITION = 1,
		TEST_CTL_TID_UNACK = 2,
		TEST_CTL_TID_FULL = 3,
		TEST_CTL_TID_DTT = 4,
		TEST_CTL_TID_BELOW_RANGE_TRANSITION = 5,
		TEST_CTL_TID_ACK = 6,
		TEST_CTL_TID_BELOW_RANGE_BASE = 7
	};

	mesh_gen_onoff_srv_init(&onoff, MESH_GEN_OFF);
	mesh_gen_level_srv_init(&level, 0);
	mesh_light_lightness_srv_init(&lightness, &onoff, &level);
	mesh_light_ctl_srv_init(&ctl, &lightness);
	models[0] = mesh_light_ctl_srv_model(&ctl);
	models[1] = mesh_light_ctl_temp_srv_model(&ctl);
	memset(&element, 0, sizeof(element));
	element.addr = 2;
	element.models = models;
	element.n_models = 2;

	/* The temperature-only server has both compact and transitioning status. */
	ATF_REQUIRE_EQ(0, mesh_light_ctl_cli_get(
	    TEST_ASSIGNED_MESH_OP_LIGHT_CTL_TEMPERATURE_GET, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 1000));
	ATF_CHECK_EQ(TEST_ASSIGNED_MESH_OP_LIGHT_CTL_TEMPERATURE_STATUS,
	    reply.opcode);
	ATF_CHECK_EQ(BT_MMDL111_CTL_TEMPERATURE_STATUS_BASE_LEN,
	    reply.params_len);

	memset(&temp_set, 0, sizeof(temp_set));
	temp_set.temperature = TEST_CTL_TARGET_TEMPERATURE;
	temp_set.delta_uv = TEST_CTL_TARGET_DELTA_UV;
	temp_set.tid = TEST_CTL_TID_TRANSITION;
	temp_set.transition.has_transition = 1;
	temp_set.transition.transition_time =
	    BT_MMDL111_TRANSITION_ONE_SECOND_100MS;
	temp_set.transition.delay = BT_MMDL111_DELAY_TWO_STEPS_10MS;
	ATF_REQUIRE_EQ(0, mesh_light_ctl_cli_temperature_set(&temp_set, 1,
	    pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 1000));
	ATF_CHECK_EQ(BT_MMDL111_CTL_TEMPERATURE_STATUS_TRANSITION_LEN,
	    reply.params_len);
	ATF_CHECK_EQ(TEST_CTL_TARGET_TEMPERATURE,
	    (uint16_t)(reply.params[4] | reply.params[5] << 8));
	ATF_CHECK(ctl.temperature_transition.active);
	ATF_REQUIRE_EQ(0, mesh_light_ctl_cli_get(
	    TEST_ASSIGNED_MESH_OP_LIGHT_CTL_TEMPERATURE_GET, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 1100));
	ATF_CHECK_EQ(BT_MMDL111_CTL_TEMPERATURE_STATUS_TRANSITION_LEN,
	    reply.params_len);
	ATF_REQUIRE_EQ(0, mesh_light_ctl_cli_get(
	    TEST_ASSIGNED_MESH_OP_LIGHT_CTL_GET, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 1100));
	ATF_CHECK_EQ(BT_MMDL111_CTL_STATUS_TRANSITION_LEN, reply.params_len);

	/* A repeated TID returns status without restarting the transition. */
	ATF_REQUIRE_EQ(0, mesh_light_ctl_cli_temperature_set(&temp_set, 1,
	    pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 1200));
	ATF_CHECK_EQ(BT_MMDL111_CTL_TEMPERATURE_STATUS_TRANSITION_LEN,
	    reply.params_len);
	ATF_CHECK(ctl.temperature > BT_MMDL111_CTL_TEMPERATURE_MIN);
	ATF_CHECK(ctl.temperature < TEST_CTL_TARGET_TEMPERATURE);

	ATF_REQUIRE_EQ(0, mesh_light_ctl_cli_get(
	    TEST_ASSIGNED_MESH_OP_LIGHT_CTL_TEMPERATURE_GET, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 2010));
	ATF_CHECK_EQ(BT_MMDL111_CTL_TEMPERATURE_STATUS_BASE_LEN,
	    reply.params_len);
	ATF_CHECK_EQ(TEST_CTL_TARGET_TEMPERATURE, ctl.temperature);
	ATF_CHECK_EQ(TEST_CTL_TARGET_DELTA_UV, ctl.delta_uv);

	/* Immediate unacknowledged writes update state and suppress a reply. */
	memset(&temp_set, 0, sizeof(temp_set));
	temp_set.temperature = TEST_CTL_IMMEDIATE_TEMPERATURE;
	temp_set.delta_uv = TEST_CTL_IMMEDIATE_DELTA_UV;
	temp_set.tid = TEST_CTL_TID_UNACK;
	ATF_REQUIRE_EQ(0, mesh_light_ctl_cli_temperature_set(&temp_set, 0,
	    pdu, &plen));
	memset(&reply, 0xa5, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 3000));
	ATF_CHECK_EQ(0, reply.params_len);
	ATF_CHECK_EQ(TEST_CTL_IMMEDIATE_TEMPERATURE, ctl.temperature);
	ATF_CHECK_EQ(TEST_CTL_IMMEDIATE_DELTA_UV, ctl.delta_uv);
	memset(&temp_set, 0, sizeof(temp_set));
	temp_set.temperature = TEST_CTL_ACK_TEMPERATURE;
	temp_set.delta_uv = TEST_CTL_ACK_DELTA_UV;
	temp_set.tid = TEST_CTL_TID_ACK;
	ATF_REQUIRE_EQ(0, mesh_light_ctl_cli_temperature_set(&temp_set, 1,
	    pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 3100));
	ATF_CHECK_EQ(BT_MMDL111_CTL_TEMPERATURE_STATUS_BASE_LEN,
	    reply.params_len);

	/* Full CTL transitions include both lightness and temperature targets. */
	memset(&ctl_set, 0, sizeof(ctl_set));
	ctl_set.lightness = TEST_CTL_TARGET_LIGHTNESS;
	ctl_set.temperature = TEST_CTL_FULL_TARGET_TEMPERATURE;
	ctl_set.delta_uv = TEST_CTL_FULL_TARGET_DELTA_UV;
	ctl_set.tid = TEST_CTL_TID_FULL;
	ctl_set.transition.has_transition = 1;
	ctl_set.transition.transition_time =
	    BT_MMDL111_TRANSITION_ONE_STEP_100MS;
	ATF_REQUIRE_EQ(0, mesh_light_ctl_cli_set(&ctl_set, 1, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 4000));
	ATF_CHECK_EQ(TEST_ASSIGNED_MESH_OP_LIGHT_CTL_STATUS, reply.opcode);
	ATF_CHECK_EQ(BT_MMDL111_CTL_STATUS_TRANSITION_LEN, reply.params_len);
	ATF_CHECK(lightness.transition.active);
	mesh_access_tick(&element, 1, 4100);
	ATF_CHECK_EQ(TEST_CTL_TARGET_LIGHTNESS, lightness.actual);
	ATF_CHECK_EQ(TEST_CTL_FULL_TARGET_TEMPERATURE, ctl.temperature);

	/* Server-side validation also rejects malformed and out-of-range PDUs. */
	memset(raw, 0, sizeof(raw));
	raw[0] = TEST_CTL_TARGET_TEMPERATURE & 0xff;
	raw[1] = TEST_CTL_TARGET_TEMPERATURE >> 8;
	raw[4] = TEST_CTL_TID_DTT;
	raw[5] = BT_MMDL111_TRANSITION_STEPS_MASK;
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(
	    TEST_ASSIGNED_MESH_OP_LIGHT_CTL_TEMPERATURE_SET, raw,
	    BT_MMDL111_CTL_TEMPERATURE_SET_TRANSITION_LEN, pdu, &plen));
	ATF_CHECK_EQ(0, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 5000));
	raw[0] = (BT_MMDL111_CTL_TEMPERATURE_MIN - 1) & 0xff;
	raw[1] = (BT_MMDL111_CTL_TEMPERATURE_MIN - 1) >> 8;
	raw[4] = TEST_CTL_TID_BELOW_RANGE_TRANSITION;
	raw[5] = BT_MMDL111_TRANSITION_ONE_STEP_100MS;
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(
	    TEST_ASSIGNED_MESH_OP_LIGHT_CTL_TEMPERATURE_SET, raw,
	    BT_MMDL111_CTL_TEMPERATURE_SET_TRANSITION_LEN, pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 5000));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(
	    TEST_ASSIGNED_MESH_OP_LIGHT_CTL_TEMPERATURE_SET, raw,
	    BT_MMDL111_CTL_TEMPERATURE_SET_BASE_LEN + 1, pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 5000));
	raw[0] = (BT_MMDL111_CTL_TEMPERATURE_MIN - 1) & 0xff;
	raw[1] = (BT_MMDL111_CTL_TEMPERATURE_MIN - 1) >> 8;
	raw[4] = TEST_CTL_TID_BELOW_RANGE_BASE;
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(
	    TEST_ASSIGNED_MESH_OP_LIGHT_CTL_TEMPERATURE_SET, raw,
	    BT_MMDL111_CTL_TEMPERATURE_SET_BASE_LEN, pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 5100));
	raw[0] = 0;
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(
	    TEST_ASSIGNED_MESH_OP_LIGHT_CTL_TEMPERATURE_GET, raw, 1, pdu,
	    &plen));
	ATF_CHECK_EQ(-1, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 5200));

	models[1].user = NULL;
	ATF_REQUIRE_EQ(0, mesh_light_ctl_cli_get(
	    TEST_ASSIGNED_MESH_OP_LIGHT_CTL_TEMPERATURE_GET, pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 5000));
}

ATF_TC_WITHOUT_HEAD(hsl_component_transition_matrix);
ATF_TC_BODY(hsl_component_transition_matrix, tc)
{
	struct mesh_gen_onoff_srv onoff;
	struct mesh_gen_level_srv level;
	struct mesh_light_lightness_srv lightness;
	struct mesh_light_hsl_srv hsl;
	struct mesh_light_hsl_component_set set;
	struct mesh_model models[3];
	struct mesh_element element;
	struct mesh_model_reply reply;
	uint8_t pdu[16], raw[5];
	size_t plen;
	enum {
		/* Non-normative valid component and transaction sentinels. */
		TEST_HSL_COMPONENT_HUE_TARGET = 60000,
		TEST_HSL_COMPONENT_SATURATION_ACK = 12345,
		TEST_HSL_COMPONENT_SATURATION_UNACK = 23456,
		TEST_HSL_COMPONENT_IMMEDIATE_HUE = 1,
		TEST_HSL_COMPONENT_TID_HUE = 1,
		TEST_HSL_COMPONENT_TID_SAT_ACK = 2,
		TEST_HSL_COMPONENT_TID_SAT_UNACK = 3,
		TEST_HSL_COMPONENT_TID_DTT = 4,
		TEST_HSL_COMPONENT_TID_IMMEDIATE = 5,
		TEST_HSL_COMPONENT_TID_WRAP = 6,
		TEST_HSL_COMPONENT_WRAP_MIN = 0xff00,
		TEST_HSL_COMPONENT_WRAP_MAX = 0x0100,
		TEST_HSL_COMPONENT_WRAP_PRESENT = 0xff80,
		TEST_HSL_COMPONENT_WRAP_TARGET = 0x0080,
		TEST_HSL_COMPONENT_WRAP_MIDPOINT = 0x0000
	};

	mesh_gen_onoff_srv_init(&onoff, MESH_GEN_OFF);
	mesh_gen_level_srv_init(&level, 0);
	mesh_light_lightness_srv_init(&lightness, &onoff, &level);
	mesh_light_hsl_srv_init(&hsl, &lightness);
	models[0] = mesh_light_hsl_srv_model(&hsl);
	models[1] = mesh_light_hsl_hue_srv_model(&hsl);
	models[2] = mesh_light_hsl_sat_srv_model(&hsl);
	memset(&element, 0, sizeof(element));
	element.addr = 2; element.models = models; element.n_models = 3;

	ATF_REQUIRE_EQ(0, mesh_light_hsl_cli_get(
	    TEST_ASSIGNED_MESH_OP_LIGHT_HSL_HUE_GET, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 1000));
	ATF_CHECK_EQ(TEST_ASSIGNED_MESH_OP_LIGHT_HSL_HUE_STATUS,
	    reply.opcode);
	ATF_CHECK_EQ(BT_MMDL111_HSL_COMPONENT_STATUS_BASE_LEN,
	    reply.params_len);

	memset(&set, 0, sizeof(set));
	set.value = TEST_HSL_COMPONENT_HUE_TARGET;
	set.tid = TEST_HSL_COMPONENT_TID_HUE;
	set.transition.has_transition = 1;
	set.transition.transition_time =
	    BT_MMDL111_TRANSITION_ONE_SECOND_100MS;
	ATF_REQUIRE_EQ(0, mesh_light_hsl_cli_hue_set(&set, 1, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 1000));
	ATF_CHECK_EQ(TEST_ASSIGNED_MESH_OP_LIGHT_HSL_HUE_STATUS,
	    reply.opcode);
	ATF_CHECK_EQ(BT_MMDL111_HSL_COMPONENT_STATUS_TRANSITION_LEN,
	    reply.params_len);
	ATF_CHECK_EQ(TEST_HSL_COMPONENT_HUE_TARGET,
	    (uint16_t)(reply.params[2] | reply.params[3] << 8));
	ATF_CHECK_EQ(BT_MMDL111_TRANSITION_ONE_SECOND_100MS, reply.params[4]);

	ATF_REQUIRE_EQ(0, mesh_light_hsl_cli_get(
	    TEST_ASSIGNED_MESH_OP_LIGHT_HSL_HUE_GET, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 1500));
	ATF_CHECK_EQ(BT_MMDL111_HSL_COMPONENT_STATUS_TRANSITION_LEN,
	    reply.params_len);
	ATF_CHECK_EQ(BT_MMDL111_REMAINING_500MS, reply.params[4]);
	mesh_access_tick(&element, 1, 2000);
	ATF_CHECK_EQ(TEST_HSL_COMPONENT_HUE_TARGET, hsl.hue);

	set.value = TEST_HSL_COMPONENT_SATURATION_ACK;
	set.tid = TEST_HSL_COMPONENT_TID_SAT_ACK;
	set.transition.has_transition = 0;
	ATF_REQUIRE_EQ(0, mesh_light_hsl_cli_saturation_set(&set, 1, pdu,
	    &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 2100));
	ATF_CHECK_EQ(TEST_ASSIGNED_MESH_OP_LIGHT_HSL_SATURATION_STATUS,
	    reply.opcode);
	ATF_CHECK_EQ(BT_MMDL111_HSL_COMPONENT_STATUS_BASE_LEN,
	    reply.params_len);
	ATF_CHECK_EQ(TEST_HSL_COMPONENT_SATURATION_ACK, hsl.saturation);

	set.value = TEST_HSL_COMPONENT_SATURATION_UNACK;
	set.tid = TEST_HSL_COMPONENT_TID_SAT_UNACK;
	ATF_REQUIRE_EQ(0, mesh_light_hsl_cli_saturation_set(&set, 0, pdu,
	    &plen));
	memset(&reply, 0xa5, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 2200));
	ATF_CHECK_EQ(0, reply.params_len);
	ATF_CHECK_EQ(TEST_HSL_COMPONENT_SATURATION_UNACK, hsl.saturation);

	/* Exercise server validation independently of the client encoder. */
	memset(raw, 0, sizeof(raw));
	raw[2] = TEST_HSL_COMPONENT_TID_DTT;
	raw[3] = BT_MMDL111_TRANSITION_STEPS_MASK;
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(
	    TEST_ASSIGNED_MESH_OP_LIGHT_HSL_HUE_SET, raw,
	    BT_MMDL111_HSL_COMPONENT_SET_TRANSITION_LEN, pdu, &plen));
	ATF_CHECK_EQ(0, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 3001));
	raw[0] = TEST_HSL_COMPONENT_IMMEDIATE_HUE;
	raw[2] = TEST_HSL_COMPONENT_TID_IMMEDIATE;
	raw[3] = BT_MMDL111_TRANSITION_ONE_STEP_100MS;
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(
	    TEST_ASSIGNED_MESH_OP_LIGHT_HSL_HUE_SET, raw,
	    BT_MMDL111_HSL_COMPONENT_SET_BASE_LEN, pdu, &plen));
	ATF_CHECK_EQ(0, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 3000));
	ATF_CHECK_EQ(TEST_HSL_COMPONENT_IMMEDIATE_HUE, hsl.hue);
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(
	    TEST_ASSIGNED_MESH_OP_LIGHT_HSL_HUE_SET, raw,
	    BT_MMDL111_HSL_COMPONENT_SET_BASE_LEN + 1, pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 3000));

	/* A wrapped configured range keeps the fade on its allowed arc. */
	hsl.hue_min = TEST_HSL_COMPONENT_WRAP_MIN;
	hsl.hue_max = TEST_HSL_COMPONENT_WRAP_MAX;
	hsl.hue = TEST_HSL_COMPONENT_WRAP_PRESENT;
	set.value = TEST_HSL_COMPONENT_WRAP_TARGET;
	set.tid = TEST_HSL_COMPONENT_TID_WRAP;
	set.transition.has_transition = 1;
	set.transition.transition_time =
	    BT_MMDL111_TRANSITION_ONE_SECOND_100MS;
	set.transition.delay = 0;
	ATF_REQUIRE_EQ(0, mesh_light_hsl_cli_hue_set(&set, 1, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 4000));
	ATF_REQUIRE_EQ(0, mesh_light_hsl_cli_get(
	    TEST_ASSIGNED_MESH_OP_LIGHT_HSL_HUE_GET, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 4500));
	ATF_CHECK_EQ(TEST_HSL_COMPONENT_WRAP_MIDPOINT,
	    (uint16_t)(reply.params[0] |
	    ((uint16_t)reply.params[1] << 8)));
}

ATF_TC_WITHOUT_HEAD(lc_transition_and_setup_matrix);
ATF_TC_BODY(lc_transition_and_setup_matrix, tc)
{
	struct mesh_gen_onoff_srv onoff;
	struct mesh_gen_level_srv level;
	struct mesh_light_lightness_srv lightness;
	struct mesh_light_lc_srv lc;
	struct mesh_light_lc_onoff_set set;
	struct mesh_model models[2];
	struct mesh_element element;
	struct mesh_model_reply reply;
	/* Device Properties §3.3: 0x0030 uses 2-octet Perceived Lightness. */
	uint8_t pdu[16], raw[8], value[2] = { 1, 2 };
	size_t plen;

	mesh_gen_onoff_srv_init(&onoff, MESH_GEN_OFF);
	mesh_gen_level_srv_init(&level, 0);
	mesh_light_lightness_srv_init(&lightness, &onoff, &level);
	/* 1200 is a non-normative lightness state sentinel. */
	lightness.last = 1200;
	mesh_light_lc_srv_init(&lc, &lightness);
	models[0] = mesh_light_lc_srv_model(&lc);
	models[1] = mesh_light_lc_setup_srv_model(&lc);
	memset(&element, 0, sizeof(element));
	element.addr = 2; element.models = models; element.n_models = 2;

	ATF_REQUIRE_EQ(0, mesh_light_lc_cli_get(TEST_MESH_OP_LIGHT_LC_MODE_GET, 0,
	    pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 1000));
	ATF_CHECK_EQ(TEST_MESH_OP_LIGHT_LC_MODE_STATUS, reply.opcode);
	ATF_CHECK_EQ(BT_MMDL111_LC_MODE_MESSAGE_PARAMS_LEN, reply.params_len);
	ATF_REQUIRE_EQ(0, mesh_light_lc_cli_get(TEST_MESH_OP_LIGHT_LC_OM_GET, 0,
	    pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 1000));
	ATF_CHECK_EQ(TEST_MESH_OP_LIGHT_LC_OM_STATUS, reply.opcode);

	ATF_REQUIRE_EQ(0, mesh_light_lc_cli_occupancy_set(
	    BT_MMDL111_LIGHT_LC_OM_ENABLED, 1, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 1100));
	ATF_CHECK_EQ(BT_MMDL111_LIGHT_LC_OM_ENABLED, lc.occupancy_mode);
	ATF_REQUIRE_EQ(0, mesh_light_lc_cli_occupancy_set(
	    BT_MMDL111_LIGHT_LC_OM_DISABLED, 0, pdu, &plen));
	memset(&reply, 0xa5, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 1200));
	ATF_CHECK_EQ(0, reply.params_len);
	ATF_CHECK_EQ(BT_MMDL111_LIGHT_LC_OM_DISABLED, lc.occupancy_mode);

	ATF_REQUIRE_EQ(0, mesh_light_lc_cli_mode_set(
	    BT_MMDL111_LIGHT_LC_MODE_ON, 0, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 1300));
	ATF_CHECK_EQ(BT_MMDL111_LIGHT_LC_MODE_ON, lc.mode);
	memset(&set, 0, sizeof(set));
	set.light_onoff = BT_MMDL111_LIGHT_LC_MODE_ON;
	/* TID 1 and Delay 2 are non-normative transaction/timing sentinels. */
	set.tid = 1;
	set.transition.has_transition = 1;
	set.transition.transition_time =
	    BT_MMDL111_TRANSITION_ONE_SECOND_100MS;
	set.transition.delay = 2;
	ATF_REQUIRE_EQ(0, mesh_light_lc_cli_light_onoff_set(&set, 1, pdu,
	    &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 1400));
	ATF_CHECK_EQ(BT_MMDL111_LC_ONOFF_STATUS_TRANSITION_LEN,
	    reply.params_len);
	ATF_CHECK(lc.transition.active);
	ATF_REQUIRE_EQ(0, mesh_light_lc_cli_get(
	    TEST_MESH_OP_LIGHT_LC_LIGHT_ONOFF_GET, 0, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 1600));
	ATF_CHECK_EQ(BT_MMDL111_LC_ONOFF_STATUS_TRANSITION_LEN,
	    reply.params_len);
	mesh_access_tick(&element, 1, 2410);
	ATF_CHECK_EQ(1, lc.light_onoff);
	ATF_CHECK_EQ(1200, lightness.actual);

	ATF_REQUIRE_EQ(0, mesh_light_lc_cli_property_set(
	    BT_DP_LIGHT_CONTROL_LIGHTNESS_STANDBY_ID, value,
	    sizeof(value), 0, pdu, &plen));
	memset(&reply, 0xa5, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 2500));
	ATF_CHECK_EQ(0, reply.params_len);
	ATF_REQUIRE_EQ(0, mesh_light_lc_cli_get(TEST_MESH_OP_LIGHT_LC_PROPERTY_GET,
	    BT_DP_LIGHT_CONTROL_LIGHTNESS_STANDBY_ID, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 2500));
	ATF_CHECK_EQ(BT_MMDL111_LC_PROPERTY_ID_SIZE +
	    BT_GSS_PERCEIVED_LIGHTNESS_SIZE, reply.params_len);
	ATF_CHECK_EQ(0, memcmp(reply.params + 2, value, sizeof(value)));

	/* Malformed server PDUs exercise checks bypassed by the client API. */
	raw[0] = BT_MMDL111_LIGHT_LC_OM_ENABLED + 1;
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(TEST_MESH_OP_LIGHT_LC_OM_SET,
	    raw, BT_MMDL111_LC_MODE_MESSAGE_PARAMS_LEN, pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 3000));
	raw[0] = BT_MMDL111_LIGHT_LC_MODE_ON;
	/* TID 2 is a non-normative sentinel; delay zero means no delay. */
	raw[1] = 2;
	raw[2] = BT_MMDL111_TRANSITION_STEPS_MASK;
	raw[3] = 0;
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(
	    TEST_MESH_OP_LIGHT_LC_LIGHT_ONOFF_SET, raw,
	    BT_MMDL111_LC_ONOFF_SET_TRANSITION_LEN, pdu, &plen));
	/* MMDL 1.1.1 §3.2.9.2: 0x3F selects DTT or immediate. */
	ATF_CHECK_EQ(0, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 3000));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(TEST_MESH_OP_LIGHT_LC_PROPERTY_GET,
	    raw, 1, pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 3000));
	/* 0xFFFF is not one of the MMDL §6.2.4 Light LC properties. */
	raw[0] = 0xff;
	raw[1] = 0xff;
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(TEST_MESH_OP_LIGHT_LC_PROPERTY_GET,
	    raw, BT_MMDL111_LC_PROPERTY_ID_SIZE, pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_access_dispatch_at(&element, 1, 1, 2, pdu,
	    plen, &reply, 3000));
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, assigned_opcode_contract);
	ATF_TP_ADD_TC(tp, lightness_models);
	ATF_TP_ADD_TC(tp, ctl_models);
	ATF_TP_ADD_TC(tp, hsl_models);
	ATF_TP_ADD_TC(tp, xyl_models);
	ATF_TP_ADD_TC(tp, lc_models);
	ATF_TP_ADD_TC(tp, client_api_matrix);
	ATF_TP_ADD_TC(tp, client_guard_completion);
	ATF_TP_ADD_TC(tp, lightness_getters_and_unacknowledged_sets);
	ATF_TP_ADD_TC(tp, ctl_hsl_xyl_setup_dispatch_matrix);
	ATF_TP_ADD_TC(tp, ctl_temperature_transition_matrix);
	ATF_TP_ADD_TC(tp, hsl_component_transition_matrix);
	ATF_TP_ADD_TC(tp, lc_transition_and_setup_matrix);
	return (atf_no_error());
}
