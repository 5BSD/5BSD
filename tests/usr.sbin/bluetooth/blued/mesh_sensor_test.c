/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard
 */
#include <sys/types.h>
#include <atf-c.h>
#include <string.h>

#include "mesh_sensor.h"
#include "spec_mesh_sensor_oracles.h"

/* Generic valid/unknown Property ID sentinels; no characteristic semantics. */
#define TEST_SENSOR_PROPERTY_ID	0x004f
#define TEST_SENSOR_SETTING_ID	0x1234
#define TEST_SENSOR_UNKNOWN_ID	0x9999

static void
assert_sensor_assigned_contract(void)
{

	ATF_CHECK_EQ(BT_MMDL11_SENSOR_SERVER_MODEL_ID, MESH_MODEL_SENSOR_SRV);
	ATF_CHECK_EQ(BT_MMDL11_SENSOR_SETUP_SERVER_MODEL_ID,
	    MESH_MODEL_SENSOR_SETUP_SRV);
	ATF_CHECK_EQ(BT_MMDL11_SENSOR_CLIENT_MODEL_ID, MESH_MODEL_SENSOR_CLI);
	ATF_CHECK_EQ(BT_MMDL11_OP_SENSOR_DESCRIPTOR_GET,
	    MESH_OP_SENSOR_DESCRIPTOR_GET);
	ATF_CHECK_EQ(BT_MMDL11_OP_SENSOR_GET, MESH_OP_SENSOR_GET);
	ATF_CHECK_EQ(BT_MMDL11_OP_SENSOR_COLUMN_GET, MESH_OP_SENSOR_COLUMN_GET);
	ATF_CHECK_EQ(BT_MMDL11_OP_SENSOR_SERIES_GET, MESH_OP_SENSOR_SERIES_GET);
	ATF_CHECK_EQ(BT_MMDL11_OP_SENSOR_CADENCE_GET, MESH_OP_SENSOR_CADENCE_GET);
	ATF_CHECK_EQ(BT_MMDL11_OP_SENSOR_SETTINGS_GET,
	    MESH_OP_SENSOR_SETTINGS_GET);
	ATF_CHECK_EQ(BT_MMDL11_OP_SENSOR_SETTING_GET, MESH_OP_SENSOR_SETTING_GET);
	ATF_CHECK_EQ(BT_MMDL11_OP_SENSOR_DESCRIPTOR_STATUS,
	    MESH_OP_SENSOR_DESCRIPTOR_STATUS);
	ATF_CHECK_EQ(BT_MMDL11_OP_SENSOR_STATUS, MESH_OP_SENSOR_STATUS);
	ATF_CHECK_EQ(BT_MMDL11_OP_SENSOR_COLUMN_STATUS,
	    MESH_OP_SENSOR_COLUMN_STATUS);
	ATF_CHECK_EQ(BT_MMDL11_OP_SENSOR_SERIES_STATUS,
	    MESH_OP_SENSOR_SERIES_STATUS);
	ATF_CHECK_EQ(BT_MMDL11_OP_SENSOR_CADENCE_SET, MESH_OP_SENSOR_CADENCE_SET);
	ATF_CHECK_EQ(BT_MMDL11_OP_SENSOR_CADENCE_SET_UNACK,
	    MESH_OP_SENSOR_CADENCE_SET_UNACK);
	ATF_CHECK_EQ(BT_MMDL11_OP_SENSOR_CADENCE_STATUS,
	    MESH_OP_SENSOR_CADENCE_STATUS);
	ATF_CHECK_EQ(BT_MMDL11_OP_SENSOR_SETTINGS_STATUS,
	    MESH_OP_SENSOR_SETTINGS_STATUS);
	ATF_CHECK_EQ(BT_MMDL11_OP_SENSOR_SETTING_SET, MESH_OP_SENSOR_SETTING_SET);
	ATF_CHECK_EQ(BT_MMDL11_OP_SENSOR_SETTING_SET_UNACK,
	    MESH_OP_SENSOR_SETTING_SET_UNACK);
	ATF_CHECK_EQ(BT_MMDL11_OP_SENSOR_SETTING_STATUS,
	    MESH_OP_SENSOR_SETTING_STATUS);
}

static int sensor_cmp_calls;

static int
sensor_test_cmp(const uint8_t *a, const uint8_t *b, size_t len, void *arg)
{

	ATF_CHECK_EQ(arg, &sensor_cmp_calls);
	sensor_cmp_calls++;
	return (memcmp(a, b, len));
}

ATF_TC_WITHOUT_HEAD(sensor_wire_and_registry);
ATF_TC_BODY(sensor_wire_and_registry, tc)
{
	struct mesh_sensor_descriptor d = {
	    TEST_SENSOR_PROPERTY_ID, 1, 2, 3, 4, 5
	}, decoded;
	struct mesh_sensor_srv srv;
	struct mesh_sensor_value v, vd;
	struct mesh_sensor_cli cli;
	uint8_t wire[40], bad[8], raw[] = { 0x11, 0x22 };
	size_t len, old_len, used;

	assert_sensor_assigned_contract();
	ATF_REQUIRE_EQ(0, mesh_sensor_descriptor_encode(&d, wire));
	ATF_REQUIRE_EQ(0, mesh_sensor_descriptor_decode(wire,
	    BT_MMDL11_SENSOR_DESCRIPTOR_SIZE, &decoded));
	ATF_CHECK_EQ(d.property_id, decoded.property_id);
	memset(&v, 0, sizeof(v)); v.property_id = d.property_id;
	memcpy(v.raw, raw, sizeof(raw)); v.raw_len = sizeof(raw);
	ATF_REQUIRE_EQ(0, mesh_sensor_value_encode(&v, wire, sizeof(wire), &len));
	ATF_REQUIRE_EQ(0, mesh_sensor_value_decode(wire, len, &vd, &used));
	ATF_CHECK_EQ(len, used); ATF_CHECK_EQ(2u, vd.raw_len);
	/* Tables 4.34/4.36: Format-B Length=0x7f plus tag=1 serializes 0xff. */
	v.property_id = TEST_SENSOR_SETTING_ID; v.raw_len = 0;
	ATF_REQUIRE_EQ(0, mesh_sensor_value_encode(&v, wire, sizeof(wire), &len));
	ATF_CHECK_EQ(BT_MMDL11_SENSOR_MPID_FORMAT_B_UNKNOWN_HEADER, wire[0]);
	ATF_REQUIRE_EQ(0, mesh_sensor_value_decode(wire, len, &vd, &used));
	ATF_CHECK_EQ(0u, vd.raw_len);
	mesh_sensor_srv_init(&srv);
	ATF_REQUIRE_EQ(0, mesh_sensor_srv_set(&srv, &d, raw, sizeof(raw)));
	ATF_REQUIRE(mesh_sensor_srv_find(&srv, d.property_id) != NULL);
	ATF_CHECK_EQ(MESH_MODEL_SENSOR_SRV, mesh_sensor_srv_model(&srv).model_id);
	mesh_sensor_cli_init(&cli);
	ATF_REQUIRE_EQ(0, mesh_sensor_cli_get(d.property_id, wire, &len));
	ATF_CHECK_EQ(4u, len);
	memset(&v, 0, sizeof(v)); v.property_id = d.property_id;
	memcpy(v.raw, raw, sizeof(raw)); v.raw_len = sizeof(raw);
	ATF_REQUIRE_EQ(0, mesh_sensor_value_encode(&v, wire, sizeof(wire), &len));
	ATF_REQUIRE_EQ(0, mesh_sensor_cli_recv(&cli, MESH_OP_SENSOR_STATUS,
	    wire, len));
	ATF_CHECK_EQ(1u, cli.n_values);
	old_len = cli.last_status_len;
	bad[0] = 0xff; bad[1] = 0; bad[2] = 0;
	ATF_REQUIRE_EQ(-1, mesh_sensor_cli_recv(&cli, MESH_OP_SENSOR_STATUS,
	    bad, 3));
	ATF_CHECK_EQ(1u, cli.n_values);
	ATF_CHECK_EQ(d.property_id, cli.values[0].property_id);
	ATF_CHECK_EQ(old_len, cli.last_status_len);

	cli.n_descriptors = 7;
	memset(bad, 0, sizeof(bad));
	ATF_REQUIRE_EQ(-1, mesh_sensor_cli_recv(&cli,
	    MESH_OP_SENSOR_DESCRIPTOR_STATUS, bad, sizeof(bad)));
	ATF_CHECK_EQ(7u, cli.n_descriptors);
	ATF_CHECK_EQ(old_len, cli.last_status_len);
}

ATF_TC_WITHOUT_HEAD(sensor_setup_and_series);
ATF_TC_BODY(sensor_setup_and_series, tc)
{
	struct mesh_sensor_srv srv;
	struct mesh_sensor_descriptor d = {
	    TEST_SENSOR_PROPERTY_ID, 0, 0, 1, 0, 0
	};
	struct mesh_sensor_cadence cadence;
	struct mesh_sensor_setting setting;
	struct mesh_sensor_column column;
	struct mesh_model models[2];
	struct mesh_element el;
	struct mesh_model_reply reply;
	uint8_t pdu[32], params[16], raw[] = { 1, 2 };
	size_t plen;

	assert_sensor_assigned_contract();
	mesh_sensor_srv_init(&srv);
	ATF_REQUIRE_EQ(0, mesh_sensor_srv_set(&srv, &d, raw, sizeof(raw)));
	memset(&cadence, 0, sizeof(cadence)); cadence.fast_period_divisor = 2;
	cadence.delta_down[0] = 1; cadence.delta_up[0] = 2;
	cadence.min_interval = 3; cadence.fast_low[0] = 4; cadence.fast_high[0] = 5;
	ATF_REQUIRE_EQ(0, mesh_sensor_srv_set_cadence(&srv, d.property_id,
	    &cadence));
	memset(&setting, 0, sizeof(setting));
	setting.property_id = TEST_SENSOR_SETTING_ID;
	setting.access = BT_MMDL11_SENSOR_SETTING_ACCESS_READ_WRITE;
	setting.raw[0] = 9; setting.raw_len = 1;
	ATF_REQUIRE_EQ(0, mesh_sensor_srv_set_setting(&srv, d.property_id,
	    &setting));
	memset(&column, 0, sizeof(column)); column.key[0] = 7; column.key_len = 1;
	column.raw[0] = 7; column.raw[1] = 8; column.raw_len = 2;
	ATF_REQUIRE_EQ(0, mesh_sensor_srv_set_column(&srv, d.property_id, &column));
	ATF_CHECK_EQ(-1, mesh_sensor_srv_set_column_comparator(&srv, 0xffff,
	    sensor_test_cmp, &sensor_cmp_calls));
	ATF_REQUIRE_EQ(0, mesh_sensor_srv_set_column_comparator(&srv,
	    d.property_id, NULL, NULL));
	column.key[0] = 9;
	column.raw[0] = 9;
	ATF_REQUIRE_EQ(0, mesh_sensor_srv_set_column(&srv, d.property_id, &column));
	models[0] = mesh_sensor_srv_model(&srv);
	models[1] = mesh_sensor_setup_srv_model(&srv);
	memset(&el, 0, sizeof(el)); el.addr = 2; el.models = models; el.n_models = 2;
	params[0] = 0x4f; params[1] = 0;
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(MESH_OP_SENSOR_CADENCE_GET,
	    params, 2, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen, &reply));
	ATF_CHECK_EQ(MESH_OP_SENSOR_CADENCE_STATUS, reply.opcode);
	ATF_CHECK_EQ(12u, reply.params_len);
	params[2] = 7;
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(MESH_OP_SENSOR_COLUMN_GET,
	    params, 3, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen, &reply));
	ATF_CHECK_EQ(MESH_OP_SENSOR_COLUMN_STATUS, reply.opcode);
	ATF_CHECK_EQ(4u, reply.params_len);
	/* Series bounds exercise both the default and configured comparators. */
	params[2] = 6; params[3] = 8;
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(MESH_OP_SENSOR_SERIES_GET,
	    params, 4, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen, &reply));
	ATF_CHECK_EQ(4u, reply.params_len);
	sensor_cmp_calls = 0;
	ATF_REQUIRE_EQ(0, mesh_sensor_srv_set_column_comparator(&srv,
	    d.property_id, sensor_test_cmp, &sensor_cmp_calls));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen, &reply));
	ATF_CHECK(sensor_cmp_calls > 0);

	/* Acknowledged and unacknowledged Cadence Set update the server state. */
	params[0] = 0x4f; params[1] = 0; params[2] = 1;
	params[3] = 1; params[4] = 0; params[5] = 2; params[6] = 0;
	params[7] = 3; params[8] = 4; params[9] = 0;
	params[10] = 5; params[11] = 0;
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(MESH_OP_SENSOR_CADENCE_SET,
	    params, 12, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen, &reply));
	ATF_CHECK_EQ(MESH_OP_SENSOR_CADENCE_STATUS, reply.opcode);
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(MESH_OP_SENSOR_CADENCE_SET_UNACK,
	    params, 12, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen, &reply));
	ATF_CHECK_EQ(0, reply.have_reply);
	/* Percentage trigger deltas are two octets even for a 3-byte property. */
	ATF_REQUIRE_EQ(0, mesh_sensor_srv_set(&srv, &d,
	    (const uint8_t[]){ 1, 2, 3 }, 3));
	memset(&cadence, 0, sizeof(cadence)); cadence.trigger_type = 1;
	cadence.delta_down[0] = 1; cadence.delta_up[0] = 2;
	ATF_REQUIRE_EQ(0, mesh_sensor_srv_set_cadence(&srv, d.property_id,
	    &cadence));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(MESH_OP_SENSOR_CADENCE_GET,
	    params, 2, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&el, 1, 1, 2, pdu, plen, &reply));
	ATF_CHECK_EQ(14u, reply.params_len);
}

ATF_TC_WITHOUT_HEAD(sensor_client_procedures);
ATF_TC_BODY(sensor_client_procedures, tc)
{
	struct mesh_sensor_cadence cadence;
	struct mesh_sensor_setting setting;
	struct mesh_access_pdu ap;
	uint8_t pdu[40], key[] = { 4, 5 }, start[] = { 1, 0 };
	uint8_t end[] = { 9, 0 };
	size_t plen;

	assert_sensor_assigned_contract();
	memset(&cadence, 0, sizeof(cadence));
	cadence.fast_period_divisor = 3;
	cadence.trigger_type = 1;
	cadence.delta_down[0] = 0x11; cadence.delta_down[1] = 0x12;
	cadence.delta_up[0] = 0x21; cadence.delta_up[1] = 0x22;
	cadence.min_interval = 4;
	cadence.fast_low[0] = 1; cadence.fast_low[1] = 2;
	cadence.fast_low[2] = 3;
	cadence.fast_high[0] = 7; cadence.fast_high[1] = 8;
	cadence.fast_high[2] = 9;
	ATF_REQUIRE_EQ(0, mesh_sensor_cli_cadence_set(TEST_SENSOR_PROPERTY_ID,
	    &cadence, 3,
	    1, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(pdu, plen, &ap));
	ATF_CHECK_EQ(MESH_OP_SENSOR_CADENCE_SET, ap.opcode);
	/* property + control + two 2-byte percentage deltas + interval + ranges */
	ATF_CHECK_EQ(14u, ap.params_len);
	ATF_CHECK_EQ(0x83, ap.params[2]);

	memset(&setting, 0, sizeof(setting));
	setting.property_id = TEST_SENSOR_SETTING_ID;
	setting.raw[0] = 0xaa; setting.raw[1] = 0xbb; setting.raw_len = 2;
	ATF_REQUIRE_EQ(0, mesh_sensor_cli_setting_get(TEST_SENSOR_PROPERTY_ID,
	    TEST_SENSOR_SETTING_ID,
	    pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(pdu, plen, &ap));
	ATF_CHECK_EQ(MESH_OP_SENSOR_SETTING_GET, ap.opcode);
	ATF_CHECK_EQ(4u, ap.params_len);
	ATF_REQUIRE_EQ(0, mesh_sensor_cli_setting_set(TEST_SENSOR_PROPERTY_ID,
	    &setting, 0,
	    pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(pdu, plen, &ap));
	ATF_CHECK_EQ(MESH_OP_SENSOR_SETTING_SET_UNACK, ap.opcode);
	ATF_CHECK_EQ(6u, ap.params_len);

	ATF_REQUIRE_EQ(0, mesh_sensor_cli_column_get(TEST_SENSOR_PROPERTY_ID, key,
	    sizeof(key), pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(pdu, plen, &ap));
	ATF_CHECK_EQ(MESH_OP_SENSOR_COLUMN_GET, ap.opcode);
	ATF_CHECK_EQ(4u, ap.params_len);
	ATF_REQUIRE_EQ(0, mesh_sensor_cli_series_get(TEST_SENSOR_PROPERTY_ID,
	    start, end,
	    sizeof(start), pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(pdu, plen, &ap));
	ATF_CHECK_EQ(MESH_OP_SENSOR_SERIES_GET, ap.opcode);
	ATF_CHECK_EQ(6u, ap.params_len);
	ATF_REQUIRE_EQ(0, mesh_sensor_cli_series_get(TEST_SENSOR_PROPERTY_ID,
	    NULL, NULL, 0,
	    pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_parse(pdu, plen, &ap));
	ATF_CHECK_EQ(2u, ap.params_len);
}

ATF_TC_WITHOUT_HEAD(sensor_client_validation_and_statuses);
ATF_TC_BODY(sensor_client_validation_and_statuses, tc)
{
	struct mesh_sensor_descriptor descriptor = { .property_id = 1 };
	struct mesh_sensor_cadence cadence;
	struct mesh_sensor_setting setting;
	struct mesh_sensor_value value;
	struct mesh_sensor_srv server;
	struct mesh_sensor_cli cli;
	uint8_t pdu[40], raw[16] = { 0 };
	size_t plen, used;

	assert_sensor_assigned_contract();
	ATF_CHECK_EQ(-1, mesh_sensor_descriptor_encode(NULL, raw));
	ATF_CHECK_EQ(-1, mesh_sensor_descriptor_encode(&descriptor, NULL));
	ATF_CHECK_EQ(-1, mesh_sensor_descriptor_decode(NULL,
	    BT_MMDL11_SENSOR_DESCRIPTOR_SIZE, &descriptor));
	ATF_CHECK_EQ(-1, mesh_sensor_descriptor_decode(raw,
	    BT_MMDL11_SENSOR_DESCRIPTOR_SIZE - 1, &descriptor));
	memset(&value, 0, sizeof(value));
	ATF_CHECK_EQ(-1, mesh_sensor_value_encode(NULL, raw, sizeof(raw),
	    &plen));
	value.property_id = 1;
	value.raw_len = MESH_SENSOR_RAW_MAX + 1;
	ATF_CHECK_EQ(-1, mesh_sensor_value_encode(&value, raw, sizeof(raw),
	    &plen));
	ATF_CHECK_EQ(-1, mesh_sensor_value_decode(NULL, 1, &value, &used));
	ATF_CHECK_EQ(-1, mesh_sensor_value_decode(raw, 0, &value, &used));

	mesh_sensor_srv_init(&server);
	ATF_CHECK_EQ(-1, mesh_sensor_srv_set(NULL, &descriptor, raw, 1));
	ATF_CHECK_EQ(-1, mesh_sensor_srv_set(&server, NULL, raw, 1));
	ATF_CHECK_EQ(-1, mesh_sensor_srv_set(&server, &descriptor, NULL, 1));
	ATF_CHECK_EQ(-1, mesh_sensor_srv_set(&server, &descriptor, raw, 0));
	ATF_CHECK_EQ(-1, mesh_sensor_srv_set_cadence(&server, 1, NULL));
	ATF_CHECK_EQ(-1, mesh_sensor_srv_set_setting(&server, 1, NULL));
	ATF_CHECK_EQ(-1, mesh_sensor_srv_set_column(&server, 1, NULL));

	ATF_REQUIRE_EQ(0, mesh_sensor_cli_descriptor_get(0, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_sensor_cli_get(0, pdu, &plen));
	ATF_REQUIRE_EQ(0, mesh_sensor_cli_property_get(
	    MESH_OP_SENSOR_SETTINGS_GET, 1, pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_sensor_cli_property_get(0, 1, pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_sensor_cli_property_get(
	    MESH_OP_SENSOR_CADENCE_GET, 0, pdu, &plen));

	memset(&cadence, 0, sizeof(cadence));
	ATF_CHECK_EQ(-1, mesh_sensor_cli_cadence_set(0, &cadence, 1, 1,
	    pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_sensor_cli_cadence_set(1, NULL, 1, 1,
	    pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_sensor_cli_cadence_set(1, &cadence, 0, 1,
	    pdu, &plen));
	cadence.trigger_type = BT_MMDL11_SENSOR_TRIGGER_PERCENT + 1;
	ATF_CHECK_EQ(-1, mesh_sensor_cli_cadence_set(1, &cadence, 1, 1,
	    pdu, &plen));
	cadence.trigger_type = 0;
	cadence.fast_period_divisor = BT_MMDL11_SENSOR_FAST_DIVISOR_MAX + 1;
	ATF_CHECK_EQ(-1, mesh_sensor_cli_cadence_set(1, &cadence, 1, 1,
	    pdu, &plen));
	cadence.fast_period_divisor = 0;
	cadence.min_interval = BT_MMDL11_SENSOR_MIN_INTERVAL_MAX + 1;
	ATF_CHECK_EQ(-1, mesh_sensor_cli_cadence_set(1, &cadence, 1, 1,
	    pdu, &plen));

	memset(&setting, 0, sizeof(setting));
	ATF_CHECK_EQ(-1, mesh_sensor_cli_setting_get(0, 1, pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_sensor_cli_setting_get(1, 0, pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_sensor_cli_setting_set(1, &setting, 1, pdu,
	    &plen));
	ATF_CHECK_EQ(-1, mesh_sensor_cli_column_get(1, NULL, 1, pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_sensor_cli_column_get(1, raw, 0, pdu, &plen));
	ATF_CHECK_EQ(-1, mesh_sensor_cli_series_get(1, NULL, raw, 1, pdu,
	    &plen));

	mesh_sensor_cli_init(&cli);
	ATF_REQUIRE_EQ(0, mesh_sensor_cli_recv(&cli,
	    MESH_OP_SENSOR_DESCRIPTOR_STATUS, NULL, 0));
	ATF_REQUIRE_EQ(0, mesh_sensor_cli_recv(&cli,
	    MESH_OP_SENSOR_COLUMN_STATUS, raw, 3));
	ATF_REQUIRE_EQ(0, mesh_sensor_cli_recv(&cli,
	    MESH_OP_SENSOR_SERIES_STATUS, raw, 4));
	ATF_REQUIRE_EQ(0, mesh_sensor_cli_recv(&cli,
	    MESH_OP_SENSOR_CADENCE_STATUS, raw, 5));
	ATF_REQUIRE_EQ(0, mesh_sensor_cli_recv(&cli,
	    MESH_OP_SENSOR_SETTINGS_STATUS, raw, 6));
	ATF_REQUIRE_EQ(0, mesh_sensor_cli_recv(&cli,
	    MESH_OP_SENSOR_SETTING_STATUS, raw, 7));
	ATF_CHECK_EQ(-1, mesh_sensor_cli_recv(&cli, 0, raw, 1));
	ATF_CHECK_EQ(-1, mesh_sensor_cli_recv(NULL,
	    MESH_OP_SENSOR_STATUS, raw, 1));
}

ATF_TC_WITHOUT_HEAD(sensor_server_request_matrix);
ATF_TC_BODY(sensor_server_request_matrix, tc)
{
	struct mesh_sensor_srv server;
	struct mesh_sensor_descriptor descriptor = {
	    .property_id = TEST_SENSOR_PROPERTY_ID, .positive_tolerance = 1,
	    .negative_tolerance = 2, .sampling_function = 3,
	    .measurement_period = 4, .update_interval = 5,
	};
	struct mesh_sensor_setting setting = {
	    .property_id = TEST_SENSOR_SETTING_ID,
	    .access = BT_MMDL11_SENSOR_SETTING_ACCESS_READ_WRITE,
	    .raw = { 9 }, .raw_len = 1,
	};
	struct mesh_model models[2];
	struct mesh_element element;
	struct mesh_model_reply reply;
	uint8_t pdu[32];
	size_t plen;

	assert_sensor_assigned_contract();
	mesh_sensor_srv_init(&server);
	ATF_REQUIRE_EQ(0, mesh_sensor_srv_set(&server, &descriptor,
	    (const uint8_t[]){ 1, 2 }, 2));
	ATF_REQUIRE_EQ(0, mesh_sensor_srv_set_setting(&server,
	    descriptor.property_id, &setting));
	models[0] = mesh_sensor_srv_model(&server);
	models[1] = mesh_sensor_setup_srv_model(&server);
	memset(&element, 0, sizeof(element));
	element.addr = 2;
	element.models = models;
	element.n_models = 2;

	ATF_REQUIRE_EQ(0, mesh_sensor_cli_descriptor_get(0, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&element, 1, 1, 2, pdu, plen,
	    &reply));
	ATF_CHECK_EQ(MESH_OP_SENSOR_DESCRIPTOR_STATUS, reply.opcode);
	ATF_CHECK_EQ(8u, reply.params_len);

	ATF_REQUIRE_EQ(0, mesh_sensor_cli_get(TEST_SENSOR_UNKNOWN_ID, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&element, 1, 1, 2, pdu, plen,
	    &reply));
	ATF_CHECK_EQ(MESH_OP_SENSOR_STATUS, reply.opcode);
	ATF_CHECK_EQ(3u, reply.params_len);

	ATF_REQUIRE_EQ(0, mesh_sensor_cli_property_get(
	    MESH_OP_SENSOR_SETTINGS_GET, descriptor.property_id, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&element, 1, 1, 2, pdu, plen,
	    &reply));
	ATF_CHECK_EQ(MESH_OP_SENSOR_SETTINGS_STATUS, reply.opcode);
	ATF_CHECK_EQ(4u, reply.params_len);

	ATF_REQUIRE_EQ(0, mesh_sensor_cli_setting_get(descriptor.property_id,
	    setting.property_id, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&element, 1, 1, 2, pdu, plen,
	    &reply));
	ATF_CHECK_EQ(MESH_OP_SENSOR_SETTING_STATUS, reply.opcode);
	ATF_CHECK_EQ(6u, reply.params_len);

	/* Sensor Setting Get has exactly two Property IDs, with no suffix. */
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(MESH_OP_SENSOR_SETTING_GET,
	    (const uint8_t[]){ 0x4f, 0x00, 0x34, 0x12, 0xff }, 5,
	    pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_CHECK_EQ(-1, mesh_access_dispatch(&element, 1, 1, 2, pdu, plen,
	    &reply));
	ATF_CHECK_EQ(0, reply.have_reply);

	/* Unknown IDs still produce the shortened statuses required by MMDL. */
	ATF_REQUIRE_EQ(0, mesh_sensor_cli_property_get(
	    MESH_OP_SENSOR_SETTINGS_GET, TEST_SENSOR_UNKNOWN_ID, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&element, 1, 1, 2, pdu, plen,
	    &reply));
	ATF_CHECK_EQ(MESH_OP_SENSOR_SETTINGS_STATUS, reply.opcode);
	ATF_CHECK_EQ(2u, reply.params_len);
	ATF_CHECK_EQ(0x99, reply.params[0]);
	ATF_CHECK_EQ(0x99, reply.params[1]);
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(MESH_OP_SENSOR_CADENCE_SET,
	    (const uint8_t[]){ 0x99, 0x99, 0x00 }, 3, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&element, 1, 1, 2, pdu, plen,
	    &reply));
	ATF_CHECK_EQ(MESH_OP_SENSOR_CADENCE_STATUS, reply.opcode);
	ATF_CHECK_EQ(2u, reply.params_len);

	ATF_REQUIRE_EQ(0, mesh_sensor_cli_property_get(
	    MESH_OP_SENSOR_CADENCE_GET, TEST_SENSOR_UNKNOWN_ID, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&element, 1, 1, 2, pdu, plen,
	    &reply));
	ATF_CHECK_EQ(MESH_OP_SENSOR_CADENCE_STATUS, reply.opcode);
	ATF_CHECK_EQ(2u, reply.params_len);
	ATF_CHECK_EQ(0x99, reply.params[0]);
	ATF_CHECK_EQ(0x99, reply.params[1]);

	ATF_REQUIRE_EQ(0, mesh_sensor_cli_property_get(
	    MESH_OP_SENSOR_CADENCE_GET, descriptor.property_id, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&element, 1, 1, 2, pdu, plen,
	    &reply));
	ATF_CHECK_EQ(2u, reply.params_len);

	ATF_REQUIRE_EQ(0, mesh_sensor_cli_setting_get(TEST_SENSOR_UNKNOWN_ID,
	    0x5678,
	    pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&element, 1, 1, 2, pdu, plen,
	    &reply));
	ATF_CHECK_EQ(MESH_OP_SENSOR_SETTING_STATUS, reply.opcode);
	ATF_CHECK_EQ(4u, reply.params_len);
	ATF_CHECK_EQ(0x78, reply.params[2]);
	ATF_CHECK_EQ(0x56, reply.params[3]);

	ATF_REQUIRE_EQ(0, mesh_sensor_cli_setting_get(descriptor.property_id,
	    0x5678, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&element, 1, 1, 2, pdu, plen,
	    &reply));
	ATF_CHECK_EQ(4u, reply.params_len);

	/* A write to a read-only setting reports, but does not alter, its state. */
	setting.property_id = 0x5678;
	setting.access = BT_MMDL11_SENSOR_SETTING_ACCESS_READ;
	setting.raw[0] = 0xaa;
	ATF_REQUIRE_EQ(0, mesh_sensor_srv_set_setting(&server,
	    descriptor.property_id, &setting));
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(MESH_OP_SENSOR_SETTING_SET,
	    (const uint8_t[]){ 0x4f, 0x00, 0x78, 0x56, 0xbb }, 5,
	    pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&element, 1, 1, 2, pdu, plen,
	    &reply));
	ATF_CHECK_EQ(MESH_OP_SENSOR_SETTING_STATUS, reply.opcode);
	ATF_CHECK_EQ(6u, reply.params_len);
	ATF_CHECK_EQ(1, reply.params[4]);
	ATF_CHECK_EQ(0xaa, reply.params[5]);
	ATF_CHECK_EQ(0xaa, server.entries[0].settings[1].raw[0]);

	setting.raw[0] = 7;
	setting.property_id = TEST_SENSOR_SETTING_ID;
	setting.access = BT_MMDL11_SENSOR_SETTING_ACCESS_READ_WRITE;
	ATF_REQUIRE_EQ(0, mesh_sensor_cli_setting_set(descriptor.property_id,
	    &setting, 0, pdu, &plen));
	memset(&reply, 0xff, sizeof(reply));
	ATF_REQUIRE_EQ(0, mesh_access_dispatch(&element, 1, 1, 2, pdu, plen,
	    &reply));
	ATF_CHECK_EQ(0, reply.have_reply);
	ATF_CHECK_EQ(7, server.entries[0].settings[0].raw[0]);

	/* A truncated Cadence Set must not read params[2] or mutate state. */
	ATF_REQUIRE_EQ(0, mesh_access_pdu_build(MESH_OP_SENSOR_CADENCE_SET,
	    (const uint8_t[]){ 0x4f, 0x00 }, 2, pdu, &plen));
	memset(&reply, 0, sizeof(reply));
	ATF_CHECK_EQ(-1, mesh_access_dispatch(&element, 1, 1, 2, pdu, plen,
	    &reply));
	ATF_CHECK_EQ(0, server.entries[0].cadence.valid);

	/* Prohibited divisor (>15) and minimum interval (>26) are ignored. */
	{
		uint8_t cadence_params[12] = {
		    0x4f, 0x00, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0
		};

		ATF_REQUIRE_EQ(0, mesh_access_pdu_build(
		    MESH_OP_SENSOR_CADENCE_SET, cadence_params,
		    sizeof(cadence_params), pdu, &plen));
		ATF_CHECK_EQ(-1, mesh_access_dispatch(&element, 1, 1, 2, pdu,
		    plen, &reply));
		cadence_params[2] = 0;
		cadence_params[7] = BT_MMDL11_SENSOR_MIN_INTERVAL_MAX + 1;
		ATF_REQUIRE_EQ(0, mesh_access_pdu_build(
		    MESH_OP_SENSOR_CADENCE_SET, cadence_params,
		    sizeof(cadence_params), pdu, &plen));
		ATF_CHECK_EQ(-1, mesh_access_dispatch(&element, 1, 1, 2, pdu,
		    plen, &reply));
		ATF_CHECK_EQ(0, server.entries[0].cadence.valid);
	}
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, sensor_wire_and_registry);
	ATF_TP_ADD_TC(tp, sensor_setup_and_series);
	ATF_TP_ADD_TC(tp, sensor_client_procedures);
	ATF_TP_ADD_TC(tp, sensor_client_validation_and_statuses);
	ATF_TP_ADD_TC(tp, sensor_server_request_matrix);
	return (atf_no_error());
}
