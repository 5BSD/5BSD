/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard
 */
#ifndef _MESH_LIGHTING_H_
#define _MESH_LIGHTING_H_

#include <stdint.h>

#include "mesh_access.h"
#include "mesh_generic.h"

#define MESH_MODEL_LIGHT_LIGHTNESS_SRV       0x1300
#define MESH_MODEL_LIGHT_LIGHTNESS_SETUP_SRV 0x1301
#define MESH_MODEL_LIGHT_LIGHTNESS_CLI       0x1302
#define MESH_MODEL_LIGHT_CTL_SRV             0x1303
#define MESH_MODEL_LIGHT_CTL_SETUP_SRV       0x1304
#define MESH_MODEL_LIGHT_CTL_CLI             0x1305
#define MESH_MODEL_LIGHT_CTL_TEMP_SRV        0x1306
#define MESH_MODEL_LIGHT_HSL_SRV             0x1307
#define MESH_MODEL_LIGHT_HSL_SETUP_SRV       0x1308
#define MESH_MODEL_LIGHT_HSL_CLI             0x1309
#define MESH_MODEL_LIGHT_HSL_HUE_SRV         0x130a
#define MESH_MODEL_LIGHT_HSL_SAT_SRV         0x130b
#define MESH_MODEL_LIGHT_XYL_SRV             0x130c
#define MESH_MODEL_LIGHT_XYL_SETUP_SRV       0x130d
#define MESH_MODEL_LIGHT_XYL_CLI             0x130e
#define MESH_MODEL_LIGHT_LC_SRV              0x130f
#define MESH_MODEL_LIGHT_LC_SETUP_SRV        0x1310
#define MESH_MODEL_LIGHT_LC_CLI              0x1311

#define MESH_OP_LIGHT_LIGHTNESS_GET          0x824b
#define MESH_OP_LIGHT_LIGHTNESS_SET          0x824c
#define MESH_OP_LIGHT_LIGHTNESS_SET_UNACK    0x824d
#define MESH_OP_LIGHT_LIGHTNESS_STATUS       0x824e
#define MESH_OP_LIGHT_LIGHTNESS_LINEAR_GET   0x824f
#define MESH_OP_LIGHT_LIGHTNESS_LINEAR_SET   0x8250
#define MESH_OP_LIGHT_LIGHTNESS_LINEAR_SET_UNACK 0x8251
#define MESH_OP_LIGHT_LIGHTNESS_LINEAR_STATUS 0x8252
#define MESH_OP_LIGHT_LIGHTNESS_LAST_GET     0x8253
#define MESH_OP_LIGHT_LIGHTNESS_LAST_STATUS  0x8254
#define MESH_OP_LIGHT_LIGHTNESS_DEFAULT_GET  0x8255
#define MESH_OP_LIGHT_LIGHTNESS_DEFAULT_STATUS 0x8256
#define MESH_OP_LIGHT_LIGHTNESS_RANGE_GET    0x8257
#define MESH_OP_LIGHT_LIGHTNESS_RANGE_STATUS 0x8258
#define MESH_OP_LIGHT_LIGHTNESS_DEFAULT_SET  0x8259
#define MESH_OP_LIGHT_LIGHTNESS_DEFAULT_SET_UNACK 0x825a
#define MESH_OP_LIGHT_LIGHTNESS_RANGE_SET    0x825b
#define MESH_OP_LIGHT_LIGHTNESS_RANGE_SET_UNACK 0x825c

#define MESH_OP_LIGHT_CTL_GET                0x825d
#define MESH_OP_LIGHT_CTL_SET                0x825e
#define MESH_OP_LIGHT_CTL_SET_UNACK          0x825f
#define MESH_OP_LIGHT_CTL_STATUS             0x8260
#define MESH_OP_LIGHT_CTL_TEMPERATURE_GET    0x8261
#define MESH_OP_LIGHT_CTL_TEMPERATURE_RANGE_GET 0x8262
#define MESH_OP_LIGHT_CTL_TEMPERATURE_RANGE_STATUS 0x8263
#define MESH_OP_LIGHT_CTL_TEMPERATURE_SET    0x8264
#define MESH_OP_LIGHT_CTL_TEMPERATURE_SET_UNACK 0x8265
#define MESH_OP_LIGHT_CTL_TEMPERATURE_STATUS 0x8266
#define MESH_OP_LIGHT_CTL_DEFAULT_GET        0x8267
#define MESH_OP_LIGHT_CTL_DEFAULT_STATUS     0x8268
#define MESH_OP_LIGHT_CTL_DEFAULT_SET        0x8269
#define MESH_OP_LIGHT_CTL_DEFAULT_SET_UNACK  0x826a
#define MESH_OP_LIGHT_CTL_TEMPERATURE_RANGE_SET 0x826b
#define MESH_OP_LIGHT_CTL_TEMPERATURE_RANGE_SET_UNACK 0x826c

#define MESH_OP_LIGHT_HSL_GET                0x826d
#define MESH_OP_LIGHT_HSL_HUE_GET            0x826e
#define MESH_OP_LIGHT_HSL_HUE_SET            0x826f
#define MESH_OP_LIGHT_HSL_HUE_SET_UNACK      0x8270
#define MESH_OP_LIGHT_HSL_HUE_STATUS         0x8271
#define MESH_OP_LIGHT_HSL_SATURATION_GET     0x8272
#define MESH_OP_LIGHT_HSL_SATURATION_SET     0x8273
#define MESH_OP_LIGHT_HSL_SATURATION_SET_UNACK 0x8274
#define MESH_OP_LIGHT_HSL_SATURATION_STATUS  0x8275
#define MESH_OP_LIGHT_HSL_SET                0x8276
#define MESH_OP_LIGHT_HSL_SET_UNACK          0x8277
#define MESH_OP_LIGHT_HSL_STATUS             0x8278
#define MESH_OP_LIGHT_HSL_TARGET_GET         0x8279
#define MESH_OP_LIGHT_HSL_TARGET_STATUS      0x827a
#define MESH_OP_LIGHT_HSL_DEFAULT_GET        0x827b
#define MESH_OP_LIGHT_HSL_DEFAULT_STATUS     0x827c
#define MESH_OP_LIGHT_HSL_RANGE_GET          0x827d
#define MESH_OP_LIGHT_HSL_RANGE_STATUS       0x827e
#define MESH_OP_LIGHT_HSL_DEFAULT_SET        0x827f
#define MESH_OP_LIGHT_HSL_DEFAULT_SET_UNACK  0x8280
#define MESH_OP_LIGHT_HSL_RANGE_SET          0x8281
#define MESH_OP_LIGHT_HSL_RANGE_SET_UNACK    0x8282

#define MESH_OP_LIGHT_XYL_GET                0x8283
#define MESH_OP_LIGHT_XYL_SET                0x8284
#define MESH_OP_LIGHT_XYL_SET_UNACK          0x8285
#define MESH_OP_LIGHT_XYL_STATUS             0x8286
#define MESH_OP_LIGHT_XYL_TARGET_GET         0x8287
#define MESH_OP_LIGHT_XYL_TARGET_STATUS      0x8288
#define MESH_OP_LIGHT_XYL_DEFAULT_GET        0x8289
#define MESH_OP_LIGHT_XYL_DEFAULT_STATUS     0x828a
#define MESH_OP_LIGHT_XYL_RANGE_GET          0x828b
#define MESH_OP_LIGHT_XYL_RANGE_STATUS       0x828c
#define MESH_OP_LIGHT_XYL_DEFAULT_SET        0x828d
#define MESH_OP_LIGHT_XYL_DEFAULT_SET_UNACK  0x828e
#define MESH_OP_LIGHT_XYL_RANGE_SET          0x828f
#define MESH_OP_LIGHT_XYL_RANGE_SET_UNACK    0x8290
#define MESH_OP_LIGHT_LC_MODE_GET            0x8291
#define MESH_OP_LIGHT_LC_MODE_SET            0x8292
#define MESH_OP_LIGHT_LC_MODE_SET_UNACK      0x8293
#define MESH_OP_LIGHT_LC_MODE_STATUS         0x8294
#define MESH_OP_LIGHT_LC_OM_GET              0x8295
#define MESH_OP_LIGHT_LC_OM_SET              0x8296
#define MESH_OP_LIGHT_LC_OM_SET_UNACK        0x8297
#define MESH_OP_LIGHT_LC_OM_STATUS           0x8298
#define MESH_OP_LIGHT_LC_LIGHT_ONOFF_GET     0x8299
#define MESH_OP_LIGHT_LC_LIGHT_ONOFF_SET     0x829a
#define MESH_OP_LIGHT_LC_LIGHT_ONOFF_SET_UNACK 0x829b
#define MESH_OP_LIGHT_LC_LIGHT_ONOFF_STATUS  0x829c
#define MESH_OP_LIGHT_LC_PROPERTY_GET        0x829d
#define MESH_OP_LIGHT_LC_PROPERTY_SET        0x62
#define MESH_OP_LIGHT_LC_PROPERTY_SET_UNACK  0x63
#define MESH_OP_LIGHT_LC_PROPERTY_STATUS     0x64

struct mesh_light_transition {
	int has_transition;
	uint8_t transition_time;
	uint8_t delay;
};

struct mesh_light_lightness_set {
	uint16_t lightness;
	uint8_t tid;
	struct mesh_light_transition transition;
};

struct mesh_light_ctl_set {
	uint16_t lightness;
	uint16_t temperature;
	int16_t delta_uv;
	uint8_t tid;
	struct mesh_light_transition transition;
};

struct mesh_light_ctl_temperature_set {
	uint16_t temperature;
	int16_t delta_uv;
	uint8_t tid;
	struct mesh_light_transition transition;
};

struct mesh_light_ctl_default {
	uint16_t lightness;
	uint16_t temperature;
	int16_t delta_uv;
};

struct mesh_light_hsl_set {
	uint16_t lightness;
	uint16_t hue;
	uint16_t saturation;
	uint8_t tid;
	struct mesh_light_transition transition;
};

struct mesh_light_hsl_component_set {
	uint16_t value;
	uint8_t tid;
	struct mesh_light_transition transition;
};

struct mesh_light_hsl_triplet {
	uint16_t lightness;
	uint16_t hue;
	uint16_t saturation;
};

struct mesh_light_hsl_range {
	uint16_t hue_min;
	uint16_t hue_max;
	uint16_t saturation_min;
	uint16_t saturation_max;
};

struct mesh_light_xyl_set {
	uint16_t lightness;
	uint16_t x;
	uint16_t y;
	uint8_t tid;
	struct mesh_light_transition transition;
};

struct mesh_light_xyl_triplet {
	uint16_t lightness;
	uint16_t x;
	uint16_t y;
};

struct mesh_light_xyl_range {
	uint16_t x_min;
	uint16_t x_max;
	uint16_t y_min;
	uint16_t y_max;
};

struct mesh_light_lightness_srv {
	uint16_t actual;
	uint16_t last;
	uint16_t default_lightness;
	uint16_t range_min;
	uint16_t range_max;
	uint8_t range_status;
	uint16_t last_src;
	uint16_t last_dst;
	uint8_t last_tid;
	int tid_valid;
	uint64_t tid_expires_ms;
	struct mesh_transition_state transition;
	const struct mesh_gen_dtt_srv *dtt;
	struct mesh_gen_onoff_srv *onoff;
	struct mesh_gen_level_srv *level;
	int in_bind;		/* P-H4: guard the reverse (downward) binding */
};

struct mesh_light_lightness_cli {
	uint16_t actual;
	uint16_t linear;
	uint16_t target;
	uint8_t remaining_time;
	int has_target;
	uint16_t last;
	uint16_t default_lightness;
	uint16_t range_min;
	uint16_t range_max;
	uint8_t range_status;
};

struct mesh_light_ctl_srv {
	uint16_t temperature;
	int16_t delta_uv;
	uint16_t default_lightness;
	uint16_t default_temperature;
	int16_t default_delta_uv;
	uint16_t range_min;
	uint16_t range_max;
	uint8_t range_status;
	uint16_t last_src;
	uint16_t last_dst;
	uint8_t last_tid;
	int tid_valid;
	uint64_t tid_expires_ms;
	struct mesh_transition_state temperature_transition;
	struct mesh_transition_state delta_uv_transition;
	struct mesh_light_lightness_srv *lightness;
	struct mesh_gen_level_srv *temperature_level;
	int in_bind;		/* P-H4: guard the reverse (downward) binding */
};

struct mesh_light_ctl_cli {
	uint16_t lightness;
	uint16_t temperature;
	int16_t delta_uv;
	uint16_t target_lightness;
	uint16_t target_temperature;
	int16_t target_delta_uv;
	uint8_t remaining_time;
	int has_target;
	uint16_t range_min;
	uint16_t range_max;
	uint8_t range_status;
};

struct mesh_light_hsl_srv {
	uint16_t hue;
	uint16_t saturation;
	uint16_t default_lightness, default_hue, default_saturation;
	uint16_t hue_min, hue_max, saturation_min, saturation_max;
	uint8_t range_status;
	uint16_t last_src;
	uint16_t last_dst;
	uint8_t last_tid;
	int tid_valid;
	uint64_t tid_expires_ms;
	struct mesh_transition_state hue_transition;
	struct mesh_transition_state saturation_transition;
	struct mesh_light_lightness_srv *lightness;
	struct mesh_gen_level_srv *hue_level;
	struct mesh_gen_level_srv *saturation_level;
	int in_bind;		/* P-H4: guard the reverse (downward) binding */
};

struct mesh_light_hsl_cli {
	uint16_t lightness, hue, saturation;
	uint16_t target_lightness, target_hue, target_saturation;
	uint8_t remaining_time;
	int has_target;
	uint16_t default_lightness, default_hue, default_saturation;
	uint16_t hue_min, hue_max, saturation_min, saturation_max;
	uint8_t range_status;
};

struct mesh_light_xyl_srv {
	uint16_t x, y;
	uint16_t default_lightness, default_x, default_y;
	uint16_t x_min, x_max, y_min, y_max;
	uint8_t range_status;
	uint16_t last_src;
	uint16_t last_dst;
	uint8_t last_tid;
	int tid_valid;
	uint64_t tid_expires_ms;
	struct mesh_transition_state x_transition;
	struct mesh_transition_state y_transition;
	struct mesh_light_lightness_srv *lightness;
};
struct mesh_light_xyl_cli {
	uint16_t lightness, x, y;
	uint16_t target_lightness, target_x, target_y;
	uint8_t remaining_time;
	int has_target;
	uint16_t default_lightness, default_x, default_y;
	uint16_t x_min, x_max, y_min, y_max;
	uint8_t range_status;
};

#define MESH_LIGHT_LC_MAX_PROPERTIES 18
#define MESH_LIGHT_LC_PROPERTY_VALUE_MAX 4
struct mesh_light_lc_property {
	uint16_t id;
	uint8_t len;
	uint8_t value[MESH_LIGHT_LC_PROPERTY_VALUE_MAX];
};
struct mesh_light_lc_onoff_set {
	uint8_t light_onoff;
	uint8_t tid;
	struct mesh_light_transition transition;
};
struct mesh_light_lc_srv {
	uint8_t mode, occupancy_mode, light_onoff;
	uint16_t last_src;
	uint16_t last_dst;
	uint8_t last_tid;
	int tid_valid;
	uint64_t tid_expires_ms;
	struct mesh_transition_state transition;
	struct mesh_light_lightness_srv *lightness;
	struct mesh_light_lc_property properties[MESH_LIGHT_LC_MAX_PROPERTIES];
	size_t n_properties;
};
struct mesh_light_lc_cli {
	uint8_t mode, occupancy_mode, light_onoff;
	uint8_t target_light_onoff, remaining_time;
	int has_target;
	uint16_t property_id;
	uint8_t property[MESH_LIGHT_LC_PROPERTY_VALUE_MAX];
	size_t property_len;
};

void mesh_light_lightness_srv_init(struct mesh_light_lightness_srv *,
    struct mesh_gen_onoff_srv *, struct mesh_gen_level_srv *);
int mesh_light_lightness_set_actual(struct mesh_light_lightness_srv *, uint16_t);
int mesh_light_lightness_set_linear(struct mesh_light_lightness_srv *, uint16_t);
uint16_t mesh_light_lightness_linear(uint16_t);
struct mesh_model mesh_light_lightness_srv_model(struct mesh_light_lightness_srv *);
struct mesh_model mesh_light_lightness_setup_srv_model(struct mesh_light_lightness_srv *);
void mesh_light_lightness_cli_init(struct mesh_light_lightness_cli *);
int mesh_light_lightness_cli_get(uint32_t, uint8_t *, size_t *);
int mesh_light_lightness_cli_actual_set(const struct mesh_light_lightness_set *,
    int, uint8_t *, size_t *);
int mesh_light_lightness_cli_linear_set(const struct mesh_light_lightness_set *,
    int, uint8_t *, size_t *);
int mesh_light_lightness_cli_default_set(uint16_t, int, uint8_t *, size_t *);
int mesh_light_lightness_cli_range_set(uint16_t, uint16_t, int, uint8_t *,
    size_t *);
int mesh_light_lightness_cli_recv(struct mesh_light_lightness_cli *, uint32_t,
    const uint8_t *, size_t);
void mesh_light_ctl_srv_init(struct mesh_light_ctl_srv *,
    struct mesh_light_lightness_srv *);
int mesh_light_ctl_set(struct mesh_light_ctl_srv *, uint16_t, uint16_t,
    int16_t);
struct mesh_model mesh_light_ctl_srv_model(struct mesh_light_ctl_srv *);
struct mesh_model mesh_light_ctl_setup_srv_model(struct mesh_light_ctl_srv *);
struct mesh_model mesh_light_ctl_temp_srv_model(struct mesh_light_ctl_srv *);
void mesh_light_ctl_cli_init(struct mesh_light_ctl_cli *);
int mesh_light_ctl_cli_get(uint32_t, uint8_t *, size_t *);
int mesh_light_ctl_cli_set(const struct mesh_light_ctl_set *, int, uint8_t *,
    size_t *);
int mesh_light_ctl_cli_temperature_set(
    const struct mesh_light_ctl_temperature_set *, int, uint8_t *, size_t *);
int mesh_light_ctl_cli_default_set(const struct mesh_light_ctl_default *, int,
    uint8_t *, size_t *);
int mesh_light_ctl_cli_temperature_range_set(uint16_t, uint16_t, int,
    uint8_t *, size_t *);
int mesh_light_ctl_cli_recv(struct mesh_light_ctl_cli *, uint32_t,
    const uint8_t *, size_t);
void mesh_light_hsl_srv_init(struct mesh_light_hsl_srv *,
    struct mesh_light_lightness_srv *);
int mesh_light_hsl_set(struct mesh_light_hsl_srv *, uint16_t, uint16_t,
    uint16_t);
struct mesh_model mesh_light_hsl_srv_model(struct mesh_light_hsl_srv *);
struct mesh_model mesh_light_hsl_setup_srv_model(struct mesh_light_hsl_srv *);
struct mesh_model mesh_light_hsl_hue_srv_model(struct mesh_light_hsl_srv *);
struct mesh_model mesh_light_hsl_sat_srv_model(struct mesh_light_hsl_srv *);
void mesh_light_hsl_cli_init(struct mesh_light_hsl_cli *);
int mesh_light_hsl_cli_get(uint32_t, uint8_t *, size_t *);
int mesh_light_hsl_cli_set(const struct mesh_light_hsl_set *, int, uint8_t *,
    size_t *);
int mesh_light_hsl_cli_hue_set(const struct mesh_light_hsl_component_set *, int,
    uint8_t *, size_t *);
int mesh_light_hsl_cli_saturation_set(
    const struct mesh_light_hsl_component_set *, int, uint8_t *, size_t *);
int mesh_light_hsl_cli_default_set(const struct mesh_light_hsl_triplet *, int,
    uint8_t *, size_t *);
int mesh_light_hsl_cli_range_set(const struct mesh_light_hsl_range *, int,
    uint8_t *, size_t *);
int mesh_light_hsl_cli_recv(struct mesh_light_hsl_cli *, uint32_t,
    const uint8_t *, size_t);
void mesh_light_xyl_srv_init(struct mesh_light_xyl_srv *,
    struct mesh_light_lightness_srv *);
int mesh_light_xyl_set(struct mesh_light_xyl_srv *, uint16_t, uint16_t,
    uint16_t);
struct mesh_model mesh_light_xyl_srv_model(struct mesh_light_xyl_srv *);
struct mesh_model mesh_light_xyl_setup_srv_model(struct mesh_light_xyl_srv *);
void mesh_light_xyl_cli_init(struct mesh_light_xyl_cli *);
int mesh_light_xyl_cli_get(uint32_t, uint8_t *, size_t *);
int mesh_light_xyl_cli_set(const struct mesh_light_xyl_set *, int, uint8_t *,
    size_t *);
int mesh_light_xyl_cli_default_set(const struct mesh_light_xyl_triplet *, int,
    uint8_t *, size_t *);
int mesh_light_xyl_cli_range_set(const struct mesh_light_xyl_range *, int,
    uint8_t *, size_t *);
int mesh_light_xyl_cli_recv(struct mesh_light_xyl_cli *, uint32_t,
    const uint8_t *, size_t);
void mesh_light_lc_srv_init(struct mesh_light_lc_srv *,
    struct mesh_light_lightness_srv *);
int mesh_light_lc_set(struct mesh_light_lc_srv *, uint8_t, uint8_t);
int mesh_light_lc_property_set(struct mesh_light_lc_srv *, uint16_t,
    const uint8_t *, size_t);
struct mesh_model mesh_light_lc_srv_model(struct mesh_light_lc_srv *);
struct mesh_model mesh_light_lc_setup_srv_model(struct mesh_light_lc_srv *);
void mesh_light_lc_cli_init(struct mesh_light_lc_cli *);
int mesh_light_lc_cli_get(uint32_t, uint16_t, uint8_t *, size_t *);
int mesh_light_lc_cli_mode_set(uint8_t, int, uint8_t *, size_t *);
int mesh_light_lc_cli_occupancy_set(uint8_t, int, uint8_t *, size_t *);
int mesh_light_lc_cli_light_onoff_set(const struct mesh_light_lc_onoff_set *,
    int, uint8_t *, size_t *);
int mesh_light_lc_cli_property_set(uint16_t, const uint8_t *, size_t, int,
    uint8_t *, size_t *);
int mesh_light_lc_cli_recv(struct mesh_light_lc_cli *, uint32_t,
    const uint8_t *, size_t);

#endif
