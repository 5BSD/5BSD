/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard
 */
#ifndef _MESH_SENSOR_H_
#define _MESH_SENSOR_H_

#include <stddef.h>
#include <stdint.h>

#include "mesh_access.h"

#define MESH_MODEL_SENSOR_SRV		0x1100
#define MESH_MODEL_SENSOR_SETUP_SRV	0x1101
#define MESH_MODEL_SENSOR_CLI		0x1102

#define MESH_OP_SENSOR_DESCRIPTOR_GET	0x8230u
#define MESH_OP_SENSOR_GET		0x8231u
#define MESH_OP_SENSOR_COLUMN_GET	0x8232u
#define MESH_OP_SENSOR_SERIES_GET	0x8233u
#define MESH_OP_SENSOR_CADENCE_GET	0x8234u
#define MESH_OP_SENSOR_SETTINGS_GET	0x8235u
#define MESH_OP_SENSOR_SETTING_GET	0x8236u
#define MESH_OP_SENSOR_DESCRIPTOR_STATUS 0x51u
#define MESH_OP_SENSOR_STATUS		0x52u
#define MESH_OP_SENSOR_COLUMN_STATUS	0x53u
#define MESH_OP_SENSOR_SERIES_STATUS	0x54u
#define MESH_OP_SENSOR_CADENCE_SET	0x55u
#define MESH_OP_SENSOR_CADENCE_SET_UNACK 0x56u
#define MESH_OP_SENSOR_CADENCE_STATUS	0x57u
#define MESH_OP_SENSOR_SETTINGS_STATUS	0x58u
#define MESH_OP_SENSOR_SETTING_SET	0x59u
#define MESH_OP_SENSOR_SETTING_SET_UNACK 0x5au
#define MESH_OP_SENSOR_SETTING_STATUS	0x5bu

#define MESH_SENSOR_RAW_MAX	32
#define MESH_SENSOR_MAX_PROPERTIES 8
#define MESH_SENSOR_MAX_SETTINGS 4
#define MESH_SENSOR_MAX_COLUMNS 4

struct mesh_sensor_cadence {
	int valid;
	uint8_t fast_period_divisor;
	uint8_t trigger_type;
	uint8_t delta_down[MESH_SENSOR_RAW_MAX];
	uint8_t delta_up[MESH_SENSOR_RAW_MAX];
	uint8_t min_interval;
	uint8_t fast_low[MESH_SENSOR_RAW_MAX];
	uint8_t fast_high[MESH_SENSOR_RAW_MAX];
};

struct mesh_sensor_setting {
	uint16_t property_id;
	uint8_t access; /* 0x01 read-only, 0x03 read/write */
	uint8_t raw[MESH_SENSOR_RAW_MAX];
	size_t raw_len;
};

struct mesh_sensor_column {
	uint8_t key[MESH_SENSOR_RAW_MAX];
	size_t key_len;
	uint8_t raw[MESH_SENSOR_RAW_MAX]; /* A || optional B || C */
	size_t raw_len;
};

typedef int (*mesh_sensor_column_cmp_fn)(const uint8_t *, const uint8_t *,
	    size_t, void *);

struct mesh_sensor_descriptor {
	uint16_t property_id;
	uint16_t positive_tolerance; /* 12-bit */
	uint16_t negative_tolerance; /* 12-bit */
	uint8_t sampling_function;
	uint8_t measurement_period;
	uint8_t update_interval;
};

struct mesh_sensor_value {
	uint16_t property_id;
	uint8_t raw[MESH_SENSOR_RAW_MAX];
	size_t raw_len;
};

struct mesh_sensor_entry {
	struct mesh_sensor_descriptor descriptor;
	struct mesh_sensor_value value;
	struct mesh_sensor_cadence cadence;
	struct mesh_sensor_setting settings[MESH_SENSOR_MAX_SETTINGS];
	size_t n_settings;
	struct mesh_sensor_column columns[MESH_SENSOR_MAX_COLUMNS];
	size_t n_columns;
	mesh_sensor_column_cmp_fn column_cmp;
	void *column_cmp_arg;
};

struct mesh_sensor_srv {
	struct mesh_sensor_entry entries[MESH_SENSOR_MAX_PROPERTIES];
	size_t n_entries;
};

struct mesh_sensor_cli {
	struct mesh_sensor_descriptor descriptors[MESH_SENSOR_MAX_PROPERTIES];
	size_t n_descriptors;
	struct mesh_sensor_value values[MESH_SENSOR_MAX_PROPERTIES];
	size_t n_values;
	uint8_t last_status[MESH_MODEL_REPLY_PARAMS_MAX];
	size_t last_status_len;
};

int mesh_sensor_descriptor_encode(const struct mesh_sensor_descriptor *,
	    uint8_t out[8]);
int mesh_sensor_descriptor_decode(const uint8_t *, size_t,
	    struct mesh_sensor_descriptor *);
int mesh_sensor_value_encode(const struct mesh_sensor_value *, uint8_t *,
	    size_t, size_t *);
int mesh_sensor_value_decode(const uint8_t *, size_t,
	    struct mesh_sensor_value *, size_t *);
void mesh_sensor_srv_init(struct mesh_sensor_srv *);
int mesh_sensor_srv_set(struct mesh_sensor_srv *,
	    const struct mesh_sensor_descriptor *, const uint8_t *, size_t);
int mesh_sensor_srv_set_cadence(struct mesh_sensor_srv *, uint16_t,
	    const struct mesh_sensor_cadence *);
int mesh_sensor_srv_set_setting(struct mesh_sensor_srv *, uint16_t,
	    const struct mesh_sensor_setting *);
int mesh_sensor_srv_set_column(struct mesh_sensor_srv *, uint16_t,
	    const struct mesh_sensor_column *);
int mesh_sensor_srv_set_column_comparator(struct mesh_sensor_srv *, uint16_t,
	    mesh_sensor_column_cmp_fn, void *);
const struct mesh_sensor_entry *mesh_sensor_srv_find(
	    const struct mesh_sensor_srv *, uint16_t);
struct mesh_model mesh_sensor_srv_model(struct mesh_sensor_srv *);
struct mesh_model mesh_sensor_setup_srv_model(struct mesh_sensor_srv *);
void mesh_sensor_cli_init(struct mesh_sensor_cli *);
int mesh_sensor_cli_descriptor_get(uint16_t, uint8_t *, size_t *);
int mesh_sensor_cli_get(uint16_t, uint8_t *, size_t *);
int mesh_sensor_cli_property_get(uint32_t, uint16_t, uint8_t *, size_t *);
int mesh_sensor_cli_cadence_set(uint16_t, const struct mesh_sensor_cadence *,
	    size_t, int, uint8_t *, size_t *);
int mesh_sensor_cli_setting_get(uint16_t, uint16_t, uint8_t *, size_t *);
int mesh_sensor_cli_setting_set(uint16_t, const struct mesh_sensor_setting *,
	    int, uint8_t *, size_t *);
int mesh_sensor_cli_column_get(uint16_t, const uint8_t *, size_t,
	    uint8_t *, size_t *);
int mesh_sensor_cli_series_get(uint16_t, const uint8_t *, const uint8_t *,
	    size_t, uint8_t *, size_t *);
int mesh_sensor_cli_recv(struct mesh_sensor_cli *, uint32_t,
	    const uint8_t *, size_t);

#endif
