/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard
 */
#include <sys/types.h>
#include <atf-c.h>
#include <string.h>

#include "mesh_time_scene.h"
#include "spec_mesh_time_scene_oracles.h"

static void
assert_time_scene_assigned_contract(void)
{
	/* Bluetooth Assigned Numbers and Mesh Model 1.1.1 Tables 5.16-5.44. */
	ATF_CHECK_EQ(BT_MMDL11_TIME_SERVER_MODEL_ID, MESH_MODEL_TIME_SRV);
	ATF_CHECK_EQ(BT_MMDL11_TIME_SETUP_SERVER_MODEL_ID,
	    MESH_MODEL_TIME_SETUP_SRV);
	ATF_CHECK_EQ(BT_MMDL11_SCENE_SERVER_MODEL_ID, MESH_MODEL_SCENE_SRV);
	ATF_CHECK_EQ(BT_MMDL11_SCENE_SETUP_SERVER_MODEL_ID,
	    MESH_MODEL_SCENE_SETUP_SRV);
	ATF_CHECK_EQ(BT_MMDL11_SCHEDULER_SERVER_MODEL_ID,
	    MESH_MODEL_SCHEDULER_SRV);
	ATF_CHECK_EQ(BT_MMDL11_SCHEDULER_SETUP_SERVER_MODEL_ID,
	    MESH_MODEL_SCHEDULER_SETUP_SRV);
	ATF_CHECK_EQ(BT_MMDL11_OP_TIME_GET, MESH_OP_TIME_GET);
	ATF_CHECK_EQ(BT_MMDL11_OP_TIME_STATUS, MESH_OP_TIME_STATUS);
	ATF_CHECK_EQ(BT_MMDL11_OP_TIME_ROLE_SET, MESH_OP_TIME_ROLE_SET);
	ATF_CHECK_EQ(BT_MMDL11_OP_TIME_ROLE_STATUS, MESH_OP_TIME_ROLE_STATUS);
	ATF_CHECK_EQ(BT_MMDL11_OP_TIME_ZONE_STATUS, MESH_OP_TIME_ZONE_STATUS);
	ATF_CHECK_EQ(BT_MMDL11_OP_TAI_UTC_DELTA_SET,
	    MESH_OP_TAI_UTC_DELTA_SET);
	ATF_CHECK_EQ(BT_MMDL11_OP_TAI_UTC_DELTA_STATUS,
	    MESH_OP_TAI_UTC_DELTA_STATUS);
	ATF_CHECK_EQ(BT_MMDL11_OP_SCENE_RECALL, MESH_OP_SCENE_RECALL);
	ATF_CHECK_EQ(BT_MMDL11_OP_SCENE_RECALL_UNACK,
	    MESH_OP_SCENE_RECALL_UNACK);
	ATF_CHECK_EQ(BT_MMDL11_OP_SCENE_REGISTER_STATUS,
	    MESH_OP_SCENE_REGISTER_STATUS);
	ATF_CHECK_EQ(BT_MMDL11_OP_SCENE_DELETE, MESH_OP_SCENE_DELETE);
	ATF_CHECK_EQ(BT_MMDL11_OP_SCENE_STATUS, MESH_OP_SCENE_STATUS);
	ATF_CHECK_EQ(BT_MMDL11_OP_SCHEDULER_GET, MESH_OP_SCHEDULER_GET);
	ATF_CHECK_EQ(BT_MMDL11_OP_SCHEDULER_STATUS,
	    MESH_OP_SCHEDULER_STATUS);
	ATF_CHECK_EQ(BT_MMDL11_OP_SCHEDULER_ACTION_STATUS,
	    MESH_OP_SCHEDULER_ACTION_STATUS);
	ATF_CHECK_EQ(BT_MMDL11_TIME_TAI_MAX, MESH_TIME_TAI_MAX);
	ATF_CHECK_EQ(BT_MMDL11_SCENE_REGISTER_ENTRIES, MESH_SCENE_MAX);
	ATF_CHECK_EQ(BT_MMDL11_SCHEDULER_ENTRIES, MESH_SCHEDULER_MAX);
}

static int
scene_capture(void *arg, uint8_t *out, size_t cap, size_t *len)
{
	if (arg == NULL || out == NULL || cap < 1 || len == NULL) return (-1);
	out[0] = *(uint8_t *)arg; *len = 1; return (0);
}

static int
scene_recall(void *arg, const uint8_t *in, size_t len)
{
	if (arg == NULL || in == NULL || len != 1) return (-1);
	*(uint8_t *)arg = in[0]; return (0);
}

static int
scene_capture_fail(void *arg __unused, uint8_t *out, size_t cap, size_t *len)
{
	if (cap != 0)
		out[0] = 0xaa;
	*len = 1;
	return (-1);
}

static int
scene_capture_oversize(void *arg __unused, uint8_t *out __unused, size_t cap,
    size_t *len)
{
	*len = cap + 1;
	return (0);
}

/*
 * Finding 6 regression: MMDL Section 1.5 packs Time Authority in BIT 0 and
 * TAI-UTC Delta in BITS 1..15 of the little-endian 16-bit word at octets 7-8.
 * The previous code put Time Authority in bit 15 and the delta in bits 0..14,
 * so against a compliant peer every Time Status/Set decoded with the delta
 * shifted and the authority read from the delta's LSB.
 */
ATF_TC_WITHOUT_HEAD(time_codec);
ATF_TC_BODY(time_codec, tc)
{
	struct mesh_time_state a, b;
	uint16_t word;
	/*
	 * TAI-UTC Delta 0x1234 (bits 1..15) and Time Authority 1 (bit 0):
	 *   packed = (0x1234 << 1) | 1 = 0x2469  ->  LE octets 0x69, 0x24.
	 */
	static const uint8_t expected[BT_MMDL11_TIME_STATE_SIZE] = {
		0x05, 0x04, 0x03, 0x02, 0x01, 0x06, 0x07, 0x69, 0x24, 0x40
	};
	uint8_t wire[BT_MMDL11_TIME_STATE_SIZE];

	assert_time_scene_assigned_contract();
	memset(&a, 0, sizeof(a));
	a.tai_seconds = UINT64_C(0x0102030405); a.subsecond = 6;
	a.uncertainty = 7; a.tai_utc_delta = 0x1234;
	a.time_authority = 1; a.time_zone_offset = 0x40;
	ATF_REQUIRE_EQ(0, mesh_time_state_encode(&a, wire));
	ATF_CHECK_EQ(0, memcmp(expected, wire, sizeof(expected)));

	/* Time Authority is bit 0; TAI-UTC Delta is bits 1..15. */
	word = (uint16_t)wire[7] | ((uint16_t)wire[8] << 8);
	ATF_CHECK_EQ_MSG(1u, (unsigned)(word & 0x0001),
	    "Time Authority must occupy bit 0");
	ATF_CHECK_EQ_MSG(0x1234u, (unsigned)(word >> 1),
	    "TAI-UTC Delta must occupy bits 1..15");

	ATF_REQUIRE_EQ(0, mesh_time_state_decode(wire, sizeof(wire), &b));
	ATF_CHECK_EQ(a.tai_seconds, b.tai_seconds);
	ATF_CHECK_EQ(a.tai_utc_delta, b.tai_utc_delta);
	ATF_CHECK_EQ(a.time_authority, b.time_authority);

	/* A max delta with authority 0 must not bleed into the authority bit. */
	memset(&a, 0, sizeof(a));
	a.tai_utc_delta = 0x7fff; a.time_authority = 0;
	ATF_REQUIRE_EQ(0, mesh_time_state_encode(&a, wire));
	word = (uint16_t)wire[7] | ((uint16_t)wire[8] << 8);
	ATF_CHECK_EQ(0u, (unsigned)(word & 0x0001));
	ATF_CHECK_EQ(0x7fffu, (unsigned)(word >> 1));
	ATF_REQUIRE_EQ(0, mesh_time_state_decode(wire, sizeof(wire), &b));
	ATF_CHECK_EQ(0x7fffu, b.tai_utc_delta);
	ATF_CHECK_EQ(0u, b.time_authority);

	a.tai_seconds = BT_MMDL11_TIME_TAI_MAX + 1;
	ATF_CHECK_EQ(-1, mesh_time_state_encode(&a, wire));
}

ATF_TC_WITHOUT_HEAD(time_models_and_client);
ATF_TC_BODY(time_models_and_client, tc)
{
	struct mesh_time_srv srv;
	struct mesh_time_cli cli;
	struct mesh_model models[2];
	struct mesh_element el;
	struct mesh_model_reply reply;
	struct mesh_access_pdu ap;
	uint8_t pdu[24];
	size_t plen;

	assert_time_scene_assigned_contract();
	mesh_time_srv_init(&srv);
	models[0] = mesh_time_srv_model(&srv);
	models[1] = mesh_time_setup_srv_model(&srv);
	memset(&el, 0, sizeof(el)); el.addr = 2; el.models = models; el.n_models = 2;
	ATF_REQUIRE_EQ(0, mesh_time_cli_get(pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen, &reply));
	ATF_CHECK_EQ(MESH_OP_TIME_STATUS, reply.opcode);
	ATF_CHECK_EQ(5u, reply.params_len);
	ATF_REQUIRE_EQ(0, mesh_time_cli_zone_set(0x44, 100, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen, &reply));
	ATF_CHECK_EQ(MESH_OP_TIME_ZONE_STATUS, reply.opcode);
	ATF_CHECK_EQ(0x40, reply.params[0]); ATF_CHECK_EQ(0x44, reply.params[1]);
	mesh_time_srv_tick(&srv, 100); ATF_CHECK_EQ(0x44, srv.time.time_zone_offset);
	ATF_REQUIRE_EQ(0, mesh_time_cli_delta_set(0x1234, 200, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(pdu, plen, &ap));
	ATF_CHECK_EQ(MESH_OP_TAI_UTC_DELTA_SET, ap.opcode);
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen, &reply));
	mesh_time_cli_init(&cli);
	ATF_REQUIRE_EQ(0, mesh_time_cli_recv(&cli, reply.opcode, reply.params,
	    reply.params_len));
	ATF_CHECK_EQ(0x1234, cli.new_tai_utc_delta);
	mesh_time_srv_tick(&srv, 200); ATF_CHECK_EQ(0x1234, srv.time.tai_utc_delta);
	ATF_CHECK_EQ(-1, mesh_time_cli_role_set(4, pdu, &plen));
}

ATF_TC_WITHOUT_HEAD(scene_models);
ATF_TC_BODY(scene_models, tc)
{
	struct mesh_scene_srv srv;
	struct mesh_scene_cli cli;
	struct mesh_model models[2];
	struct mesh_element el;
	struct mesh_model_reply reply;
	uint8_t value = 7, pdu[24], recall[5];
	size_t plen;

	assert_time_scene_assigned_contract();
	mesh_scene_srv_init(&srv, scene_capture, scene_recall, &value);
	models[0] = mesh_scene_srv_model(&srv);
	models[1] = mesh_scene_setup_srv_model(&srv);
	memset(&el, 0, sizeof(el)); el.addr = 2; el.models = models; el.n_models = 2;
	ATF_REQUIRE_EQ(0, mesh_scene_cli_store(0x1234, 1, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen, &reply));
	ATF_CHECK_EQ(MESH_OP_SCENE_REGISTER_STATUS, reply.opcode);
	value = 9;
	recall[0] = 0x34; recall[1] = 0x12; recall[2] = 1;
	recall[3] = 0x0a; recall[4] = 0;
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(MESH_OP_SCENE_RECALL, recall,
	    sizeof(recall), pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch_at(&el, 1, 1, 2, pdu, plen,
	    &reply, 1000));
	ATF_CHECK_EQ(9, value); ATF_CHECK_EQ(0x1234, srv.current_scene);
	ATF_CHECK_EQ(0x1234, srv.target_scene);
	mesh_access_tick(&el, 1, 1999);
	ATF_CHECK_EQ(9, value);
	mesh_access_tick(&el, 1, 2000);
	ATF_CHECK_EQ(7, value); ATF_CHECK_EQ(0x1234, srv.current_scene);
	mesh_scene_cli_init(&cli);
	ATF_REQUIRE_EQ(0, mesh_scene_cli_recv(&cli, reply.opcode, reply.params,
	    reply.params_len));
	ATF_CHECK_EQ(0x1234, cli.current_scene);
	ATF_REQUIRE_EQ(0, mesh_scene_cli_delete(0x1234, 1, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen, &reply));
	ATF_CHECK_EQ(0u, srv.n_scenes); ATF_CHECK_EQ(0, srv.current_scene);
}

ATF_TC_WITHOUT_HEAD(scene_store_failure_atomic);
ATF_TC_BODY(scene_store_failure_atomic, tc)
{
	struct mesh_scene_srv srv;
	uint8_t value = 7;

	assert_time_scene_assigned_contract();
	mesh_scene_srv_init(&srv, scene_capture_fail, scene_recall, &value);
	ATF_CHECK_EQ(-1, mesh_scene_srv_store(&srv, 0x1234));
	ATF_CHECK_EQ_MSG(0u, srv.n_scenes,
	    "failed capture inserted a ghost scene");

	srv.capture = scene_capture;
	ATF_REQUIRE_EQ(0, mesh_scene_srv_store(&srv, 0x1234));
	ATF_REQUIRE_EQ(1u, srv.n_scenes);
	ATF_REQUIRE_EQ(1u, srv.scenes[0].data_len);
	ATF_REQUIRE_EQ(7, srv.scenes[0].data[0]);

	srv.capture = scene_capture_fail;
	value = 9;
	ATF_CHECK_EQ(-1, mesh_scene_srv_store(&srv, 0x1234));
	ATF_CHECK_EQ(1u, srv.n_scenes);
	ATF_CHECK_EQ_MSG(7, srv.scenes[0].data[0],
	    "failed replacement corrupted the stored scene");
	ATF_CHECK_EQ(0x1234, srv.current_scene);

	srv.capture = scene_capture_oversize;
	ATF_CHECK_EQ(-1, mesh_scene_srv_store(&srv, 0x5678));
	ATF_CHECK_EQ_MSG(1u, srv.n_scenes,
	    "oversized capture inserted a ghost scene");
}

/*
 * Finding 8 regression: the 6 s TID transaction window must run from the
 * PREVIOUS same-TID message (MMDL Section 3.1), i.e. a retransmission refreshes
 * it.  A slow but continuous stream of same-TID Scene Recalls (t=0, 5 s, 10 s)
 * must stay ONE transaction; the previous code anchored the window at the first
 * message, so the t=10 s recall was misclassified as new and re-applied.
 */
ATF_TC_WITHOUT_HEAD(scene_tid_window_refreshes);
ATF_TC_BODY(scene_tid_window_refreshes, tc)
{
	struct mesh_scene_srv srv;
	struct mesh_model models[2];
	struct mesh_element el;
	struct mesh_model_reply reply;
	uint8_t value = 7, pdu[24];
	uint8_t params[3] = { 0x34, 0x12, 0x22 };	/* scene 0x1234, TID 0x22 */
	size_t plen;

	assert_time_scene_assigned_contract();
	mesh_scene_srv_init(&srv, scene_capture, scene_recall, &value);
	models[0] = mesh_scene_srv_model(&srv);
	models[1] = mesh_scene_setup_srv_model(&srv);
	memset(&el, 0, sizeof(el)); el.addr = 2; el.models = models; el.n_models = 2;

	/* Capture scene 0x1234 holding value 7. */
	ATF_REQUIRE_EQ(0, mesh_scene_srv_store(&srv, 0x1234));

	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(MESH_OP_SCENE_RECALL_UNACK,
	    params, sizeof(params), pdu, &plen));

	/* t=0: first message of the transaction -> recall applies (value=7). */
	value = 9;
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch_at(&el, 1, 1, 2, pdu, plen,
	    &reply, 0));
	ATF_CHECK_EQ_MSG(7, value, "first same-TID recall must apply");

	/* t=5 s: retransmission -> ignored, and refreshes the window to 11 s. */
	value = 9;
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch_at(&el, 1, 1, 2, pdu, plen,
	    &reply, 5000));
	ATF_CHECK_EQ_MSG(9, value, "retransmission at 5 s must be ignored");

	/* t=10 s: still within the refreshed window -> still ignored. */
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch_at(&el, 1, 1, 2, pdu, plen,
	    &reply, 10000));
	ATF_CHECK_EQ_MSG(9, value,
	    "same-TID recall at 10 s must remain one transaction (not re-applied)");
}

ATF_TC_WITHOUT_HEAD(scheduler_models);
ATF_TC_BODY(scheduler_models, tc)
{
	struct mesh_scheduler_action a, decoded;
	struct mesh_scheduler_srv srv;
	struct mesh_scheduler_cli cli;
	struct mesh_model models[2];
	struct mesh_element el;
	struct mesh_model_reply reply;
	uint8_t wire[BT_MMDL11_SCHEDULER_ACTION_SIZE], pdu[24];
	size_t plen;

	assert_time_scene_assigned_contract();
	/* Mesh Model 1.1.1 Table 5.15: annual July 13 Scene Recall. */
	memset(&a, 0, sizeof(a)); a.index = BT_MMDL11_SCHED_TABLE515_INDEX;
	a.year = BT_MMDL11_SCHED_TABLE515_YEAR;
	a.months = BT_MMDL11_SCHED_TABLE515_MONTHS;
	a.day = BT_MMDL11_SCHED_TABLE515_DAY;
	a.hour = BT_MMDL11_SCHED_TABLE515_HOUR;
	a.minute = BT_MMDL11_SCHED_TABLE515_MINUTE;
	a.second = BT_MMDL11_SCHED_TABLE515_SECOND;
	a.days_of_week = BT_MMDL11_SCHED_TABLE515_DOW;
	a.action = BT_MMDL11_SCHEDULER_ACTION_RECALL;
	a.transition_time = 0; a.scene_number = BT_MMDL11_SCHED_TABLE515_SCENE;
	ATF_REQUIRE_EQ(0, mesh_scheduler_action_encode(&a, wire));
	ATF_CHECK_EQ(0, memcmp(bt_mmdl11_sched_table515_wire, wire,
	    sizeof(wire)));
	ATF_REQUIRE_EQ(0, mesh_scheduler_action_decode(wire, sizeof(wire), &decoded));
	ATF_CHECK_EQ(a.months, decoded.months); ATF_CHECK_EQ(a.scene_number,
	    decoded.scene_number);
	mesh_scheduler_srv_init(&srv);
	models[0] = mesh_scheduler_srv_model(&srv);
	models[1] = mesh_scheduler_setup_srv_model(&srv);
	memset(&el, 0, sizeof(el)); el.addr = 2; el.models = models; el.n_models = 2;
	ATF_REQUIRE_EQ(0, mesh_scheduler_cli_action_set(&a, 1, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen, &reply));
	ATF_CHECK_EQ(MESH_OP_SCHEDULER_ACTION_STATUS, reply.opcode);
	ATF_CHECK((srv.defined & (1u << 3)) != 0);
	mesh_scheduler_cli_init(&cli);
	ATF_REQUIRE_EQ(0, mesh_scheduler_cli_recv(&cli, reply.opcode, reply.params,
	    reply.params_len));
	ATF_CHECK_EQ(10, cli.action.scene_number);
	a.action = 0xf; a.scene_number = 0;
	ATF_REQUIRE_EQ(0, mesh_scheduler_cli_action_set(&a, 0, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen, &reply));
	ATF_CHECK((srv.defined & (1u << 3)) == 0);
}

ATF_TC_WITHOUT_HEAD(scheduler_zero_month_mask);
ATF_TC_BODY(scheduler_zero_month_mask, tc)
{
	struct mesh_scheduler_action action, decoded;
	struct mesh_scheduler_srv srv;
	struct mesh_model model;
	struct mesh_element el;
	struct mesh_model_reply reply;
	uint8_t wire[BT_MMDL11_SCHEDULER_ACTION_SIZE], pdu[24];
	size_t plen;

	assert_time_scene_assigned_contract();
	/*
	 * Mesh Model 1.1.1 Section 5.1.4.2 and Table 5.7: an all-zero
	 * Month field is valid and means the scheduled event never triggers.
	 */
	memset(&action, 0, sizeof(action));
	action.index = 4;
	action.year = BT_MMDL11_SCHED_TABLE515_YEAR;
	action.months = 0;
	action.day = 1;
	action.hour = 1;
	action.minute = 1;
	action.second = 1;
	action.days_of_week = 1;
	action.action = 1;
	ATF_REQUIRE_EQ(0, mesh_scheduler_action_encode(&action, wire));
	ATF_REQUIRE_EQ(0, mesh_scheduler_action_decode(wire, sizeof(wire),
	    &decoded));
	ATF_CHECK_EQ(0, decoded.months);

	mesh_scheduler_srv_init(&srv);
	model = mesh_scheduler_setup_srv_model(&srv);
	memset(&el, 0, sizeof(el));
	el.addr = 2; el.models = &model; el.n_models = 1;
	ATF_REQUIRE_EQ(0, mesh_scheduler_cli_action_set(&action, 1, pdu,
	    &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen,
	    &reply));
	ATF_CHECK((srv.defined & (1u << action.index)) != 0);
}

ATF_TC_WITHOUT_HEAD(client_status_and_validation_matrix);
ATF_TC_BODY(client_status_and_validation_matrix, tc)
{
	struct mesh_time_state state;
	struct mesh_time_cli time;
	struct mesh_scene_cli scene;
	struct mesh_scheduler_cli scheduler;
	uint8_t pdu[24], raw[16] = { 0 };
	size_t plen;

	assert_time_scene_assigned_contract();
	memset(&state, 0, sizeof(state));
	state.tai_seconds = 1;
	ATF_REQUIRE_EQ(0, mesh_time_cli_set(&state, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_time_cli_role_get(pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_time_cli_role_set(3, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_time_cli_zone_get(pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_time_cli_delta_get(pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_time_cli_zone_set(0,
	    MESH_TIME_TAI_MAX + 1, pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_time_cli_delta_set(0x8000, 0, pdu, &plen));

	mesh_time_cli_init(&time);
	ATF_REQUIRE_EQ(0, mesh_time_cli_recv(&time, MESH_OP_TIME_STATUS,
	    raw, 5));
	raw[0] = 3;
	ATF_REQUIRE_EQ(0, mesh_time_cli_recv(&time, MESH_OP_TIME_ROLE_STATUS,
	    raw, 1));
	memset(raw, 0, sizeof(raw));
	raw[0] = 0x40; raw[1] = 0x41;
	ATF_REQUIRE_EQ(0, mesh_time_cli_recv(&time, MESH_OP_TIME_ZONE_STATUS,
	    raw, 7));
	ATF_REQUIRE_EQ(0, mesh_time_cli_recv(&time,
	    MESH_OP_TAI_UTC_DELTA_STATUS, raw, 9));
	raw[1] = 0x80;
	ATF_CHECK_EQ(-1, mesh_time_cli_recv(&time,
	    MESH_OP_TAI_UTC_DELTA_STATUS, raw, 9));
	ATF_CHECK_EQ(-1, mesh_time_cli_recv(&time, 0, raw, 1));

	ATF_REQUIRE_EQ(0, mesh_scene_cli_get(pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_scene_cli_register_get(pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_scene_cli_recall(1, 7, 0, pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_scene_cli_recall(0, 7, 1, pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_scene_cli_store(0, 1, pdu, &plen));
	mesh_scene_cli_init(&scene);
	memset(raw, 0, sizeof(raw));
	raw[1] = 1; raw[3] = 2; raw[5] = 3;
	ATF_REQUIRE_EQ(0, mesh_scene_cli_recv(&scene, MESH_OP_SCENE_STATUS,
	    raw, 6));
	raw[3] = 1; raw[4] = 0; raw[5] = 2; raw[6] = 0;
	ATF_REQUIRE_EQ(0, mesh_scene_cli_recv(&scene,
	    MESH_OP_SCENE_REGISTER_STATUS, raw, 7));
	ATF_CHECK_EQ(2u, scene.n_scenes);
	ATF_CHECK_EQ(-1, mesh_scene_cli_recv(&scene, 0, raw, 3));

	ATF_REQUIRE_EQ(0, mesh_scheduler_cli_get(pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_scheduler_cli_action_get(15, pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_scheduler_cli_action_get(16, pdu, &plen));
	mesh_scheduler_cli_init(&scheduler);
	raw[0] = 0x05; raw[1] = 0;
	ATF_REQUIRE_EQ(0, mesh_scheduler_cli_recv(&scheduler,
	    MESH_OP_SCHEDULER_STATUS, raw, 2));
	raw[0] = 15;
	ATF_REQUIRE_EQ(0, mesh_scheduler_cli_recv(&scheduler,
	    MESH_OP_SCHEDULER_ACTION_STATUS, raw, 1));
	raw[0] = 16;
	ATF_CHECK_EQ(-1, mesh_scheduler_cli_recv(&scheduler,
	    MESH_OP_SCHEDULER_ACTION_STATUS, raw, 1));
}

ATF_TC_WITHOUT_HEAD(server_opcode_matrix);
ATF_TC_BODY(server_opcode_matrix, tc)
{
	struct mesh_time_srv time;
	struct mesh_scene_srv scene;
	struct mesh_scheduler_srv scheduler;
	struct mesh_scheduler_action action;
	struct mesh_time_state state;
	struct mesh_model models[6];
	struct mesh_element el;
	struct mesh_model_reply reply;
	uint8_t value = 9, pdu[32], params[8];
	size_t plen;

	assert_time_scene_assigned_contract();
	mesh_time_srv_init(&time);
	mesh_scene_srv_init(&scene, scene_capture, scene_recall, &value);
	mesh_scheduler_srv_init(&scheduler);
	models[0] = mesh_time_srv_model(&time);
	models[1] = mesh_time_setup_srv_model(&time);
	models[2] = mesh_scene_srv_model(&scene);
	models[3] = mesh_scene_setup_srv_model(&scene);
	models[4] = mesh_scheduler_srv_model(&scheduler);
	models[5] = mesh_scheduler_setup_srv_model(&scheduler);
	memset(&el, 0, sizeof(el));
	el.addr = 2; el.models = models; el.n_models = 6;

	/* Populate Time and exercise every server GET/SET opcode. */
	memset(&state, 0, sizeof(state));
	state.tai_seconds = 123;
	state.time_zone_offset = 0x40;
	ATF_REQUIRE_EQ(0, mesh_time_cli_set(&state, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen,
	    &reply));
	ATF_CHECK_EQ(10u, reply.params_len);
	ATF_REQUIRE_EQ(0, mesh_time_cli_role_set(2, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen,
	    &reply));
	ATF_CHECK_EQ(2, time.role);
	ATF_REQUIRE_EQ(0, mesh_time_cli_role_get(pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen,
	    &reply));
	ATF_REQUIRE_EQ(0, mesh_time_cli_zone_get(pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen,
	    &reply));
	ATF_REQUIRE_EQ(0, mesh_time_cli_delta_get(pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen,
	    &reply));

	/* Scene Get/Register Get plus immediate acknowledged/unacknowledged recall. */
	ATF_REQUIRE_EQ(0, mesh_scene_cli_store(1, 1, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen,
	    &reply));
	ATF_REQUIRE_EQ(0, mesh_scene_cli_get(pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen,
	    &reply));
	ATF_REQUIRE_EQ(0, mesh_scene_cli_register_get(pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen,
	    &reply));
	params[0] = 1; params[1] = 0; params[2] = 8;
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(MESH_OP_SCENE_RECALL_UNACK,
	    params, 3, pdu, &plen));
	memset(&reply, 0xff, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen,
	    &reply));
	ATF_CHECK_EQ(0u, reply.params_len);

	/* Scheduler aggregate status and both defined/undefined Action Status. */
	memset(&action, 0, sizeof(action));
	action.index = 3; action.year = 0x64; action.months = 1;
	action.day = 1; action.hour = 1; action.minute = 1; action.second = 1;
	action.days_of_week = 1; action.action = 2; action.scene_number = 1;
	ATF_REQUIRE_EQ(0, mesh_scheduler_cli_action_set(&action, 1, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen,
	    &reply));
	ATF_REQUIRE_EQ(0, mesh_scheduler_cli_get(pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen,
	    &reply));
	ATF_REQUIRE_EQ(0, mesh_scheduler_cli_action_get(3, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen,
	    &reply));
	ATF_CHECK_EQ(10u, reply.params_len);
	ATF_REQUIRE_EQ(0, mesh_scheduler_cli_action_get(4, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen,
	    &reply));
	ATF_CHECK_EQ(1u, reply.params_len);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, time_codec);
	ATF_TP_ADD_TC(tp, time_models_and_client);
	ATF_TP_ADD_TC(tp, scene_models);
	ATF_TP_ADD_TC(tp, scene_store_failure_atomic);
	ATF_TP_ADD_TC(tp, scene_tid_window_refreshes);
	ATF_TP_ADD_TC(tp, scheduler_models);
	ATF_TP_ADD_TC(tp, scheduler_zero_month_mask);
	ATF_TP_ADD_TC(tp, client_status_and_validation_matrix);
	ATF_TP_ADD_TC(tp, server_opcode_matrix);
	return (atf_no_error());
}
