/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard
 */
#ifndef _MESH_TIME_SCENE_H_
#define _MESH_TIME_SCENE_H_

#include <sys/types.h>
#include <stdint.h>

#include "mesh_access.h"

struct mesh_gen_dtt_srv;

#define MESH_MODEL_TIME_SRV          0x1200
#define MESH_MODEL_TIME_SETUP_SRV    0x1201
#define MESH_MODEL_TIME_CLI          0x1202
#define MESH_MODEL_SCENE_SRV         0x1203
#define MESH_MODEL_SCENE_SETUP_SRV   0x1204
#define MESH_MODEL_SCENE_CLI         0x1205
#define MESH_MODEL_SCHEDULER_SRV     0x1206
#define MESH_MODEL_SCHEDULER_SETUP_SRV 0x1207
#define MESH_MODEL_SCHEDULER_CLI     0x1208

#define MESH_OP_TIME_GET             0x8237
#define MESH_OP_TIME_ROLE_GET        0x8238
#define MESH_OP_TIME_ROLE_SET        0x8239
#define MESH_OP_TIME_ROLE_STATUS     0x823a
#define MESH_OP_TIME_ZONE_GET        0x823b
#define MESH_OP_TIME_ZONE_SET        0x823c
#define MESH_OP_TIME_ZONE_STATUS     0x823d
#define MESH_OP_TAI_UTC_DELTA_GET    0x823e
#define MESH_OP_TAI_UTC_DELTA_SET    0x823f
#define MESH_OP_TAI_UTC_DELTA_STATUS 0x8240
#define MESH_OP_TIME_SET             0x5c
#define MESH_OP_TIME_STATUS          0x5d

#define MESH_OP_SCENE_GET            0x8241
#define MESH_OP_SCENE_RECALL         0x8242
#define MESH_OP_SCENE_RECALL_UNACK   0x8243
#define MESH_OP_SCENE_REGISTER_GET   0x8244
#define MESH_OP_SCENE_REGISTER_STATUS 0x8245
#define MESH_OP_SCENE_STORE          0x8246
#define MESH_OP_SCENE_STORE_UNACK    0x8247
#define MESH_OP_SCENE_DELETE         0x829e
#define MESH_OP_SCENE_DELETE_UNACK   0x829f
#define MESH_OP_SCENE_STATUS         0x5e

#define MESH_OP_SCHEDULER_ACTION_GET 0x8248
#define MESH_OP_SCHEDULER_GET        0x8249
#define MESH_OP_SCHEDULER_STATUS     0x824a
#define MESH_OP_SCHEDULER_ACTION_STATUS 0x5f
#define MESH_OP_SCHEDULER_ACTION_SET 0x60
#define MESH_OP_SCHEDULER_ACTION_SET_UNACK 0x61

#define MESH_TIME_TAI_MAX            UINT64_C(0xffffffffff)
#define MESH_SCENE_MAX               16
#define MESH_SCENE_DATA_MAX          128
#define MESH_SCHEDULER_MAX           16

struct mesh_time_state {
	uint64_t tai_seconds;       /* 40-bit TAI Seconds */
	uint8_t subsecond;
	uint8_t uncertainty;
	uint16_t tai_utc_delta;     /* 15-bit encoded delta */
	uint8_t time_authority;
	uint8_t time_zone_offset;
};

struct mesh_time_srv {
	struct mesh_time_state time;
	uint8_t role;
	uint8_t new_zone_offset;
	uint64_t zone_change;
	uint16_t new_tai_utc_delta;
	uint64_t delta_change;
};

struct mesh_time_cli {
	struct mesh_time_state time;
	uint8_t role;
	uint8_t current_zone_offset;
	uint8_t new_zone_offset;
	uint64_t zone_change;
	uint16_t current_tai_utc_delta;
	uint16_t new_tai_utc_delta;
	uint64_t delta_change;
	uint32_t last_opcode;
};

typedef int (*mesh_scene_capture_fn)(void *, uint8_t *, size_t, size_t *);
typedef int (*mesh_scene_recall_fn)(void *, const uint8_t *, size_t);

struct mesh_scene_entry {
	uint16_t number;
	uint8_t data[MESH_SCENE_DATA_MAX];
	size_t data_len;
};

struct mesh_scene_srv {
	struct mesh_scene_entry scenes[MESH_SCENE_MAX];
	size_t n_scenes;
	uint16_t current_scene;
	uint16_t target_scene;
	uint16_t last_src;
	uint16_t last_dst;
	uint8_t last_tid;
	int tid_valid;
	uint64_t tid_expires_ms;
	struct mesh_transition_state transition;
	const struct mesh_gen_dtt_srv *dtt;
	mesh_scene_capture_fn capture;
	mesh_scene_recall_fn recall;
	void *cb_arg;
};

struct mesh_scene_cli {
	uint8_t status;
	uint16_t current_scene;
	uint16_t target_scene;
	uint8_t remaining_time;
	uint16_t scenes[MESH_SCENE_MAX];
	size_t n_scenes;
};

struct mesh_scheduler_action {
	uint8_t index;
	uint8_t year;
	uint16_t months;
	uint8_t day;
	uint8_t hour;
	uint8_t minute;
	uint8_t second;
	uint8_t days_of_week;
	uint8_t action;
	uint8_t transition_time;
	uint16_t scene_number;
};

struct mesh_scheduler_srv {
	struct mesh_scheduler_action entries[MESH_SCHEDULER_MAX];
	uint16_t defined;
};

struct mesh_scheduler_cli {
	struct mesh_scheduler_action action;
	uint16_t defined;
	int action_present;
};

int mesh_time_state_encode(const struct mesh_time_state *, uint8_t out[10]);
int mesh_time_state_decode(const uint8_t *, size_t, struct mesh_time_state *);
void mesh_time_srv_init(struct mesh_time_srv *);
void mesh_time_srv_tick(struct mesh_time_srv *, uint64_t);
struct mesh_model mesh_time_srv_model(struct mesh_time_srv *);
struct mesh_model mesh_time_setup_srv_model(struct mesh_time_srv *);
void mesh_time_cli_init(struct mesh_time_cli *);
int mesh_time_cli_get(uint8_t *, size_t *);
int mesh_time_cli_set(const struct mesh_time_state *, uint8_t *, size_t *);
int mesh_time_cli_role_get(uint8_t *, size_t *);
int mesh_time_cli_role_set(uint8_t, uint8_t *, size_t *);
int mesh_time_cli_zone_get(uint8_t *, size_t *);
int mesh_time_cli_zone_set(uint8_t, uint64_t, uint8_t *, size_t *);
int mesh_time_cli_delta_get(uint8_t *, size_t *);
int mesh_time_cli_delta_set(uint16_t, uint64_t, uint8_t *, size_t *);
int mesh_time_cli_recv(struct mesh_time_cli *, uint32_t, const uint8_t *,
    size_t);
void mesh_scene_srv_init(struct mesh_scene_srv *, mesh_scene_capture_fn,
    mesh_scene_recall_fn, void *);
int mesh_scene_srv_store(struct mesh_scene_srv *, uint16_t);
int mesh_scene_srv_delete(struct mesh_scene_srv *, uint16_t);
int mesh_scene_srv_recall(struct mesh_scene_srv *, uint16_t);
void mesh_scene_srv_tick(struct mesh_scene_srv *, uint64_t);
struct mesh_model mesh_scene_srv_model(struct mesh_scene_srv *);
struct mesh_model mesh_scene_setup_srv_model(struct mesh_scene_srv *);
void mesh_scene_cli_init(struct mesh_scene_cli *);
int mesh_scene_cli_get(uint8_t *, size_t *);
int mesh_scene_cli_register_get(uint8_t *, size_t *);
int mesh_scene_cli_recall(uint16_t, uint8_t, int, uint8_t *, size_t *);
int mesh_scene_cli_store(uint16_t, int, uint8_t *, size_t *);
int mesh_scene_cli_delete(uint16_t, int, uint8_t *, size_t *);
int mesh_scene_cli_recv(struct mesh_scene_cli *, uint32_t, const uint8_t *,
    size_t);
int mesh_scheduler_action_encode(const struct mesh_scheduler_action *,
    uint8_t out[10]);
int mesh_scheduler_action_decode(const uint8_t *, size_t,
    struct mesh_scheduler_action *);
void mesh_scheduler_srv_init(struct mesh_scheduler_srv *);
struct mesh_model mesh_scheduler_srv_model(struct mesh_scheduler_srv *);
struct mesh_model mesh_scheduler_setup_srv_model(struct mesh_scheduler_srv *);
void mesh_scheduler_cli_init(struct mesh_scheduler_cli *);
int mesh_scheduler_cli_get(uint8_t *, size_t *);
int mesh_scheduler_cli_action_get(uint8_t, uint8_t *, size_t *);
int mesh_scheduler_cli_action_set(const struct mesh_scheduler_action *, int,
    uint8_t *, size_t *);
int mesh_scheduler_cli_recv(struct mesh_scheduler_cli *, uint32_t,
    const uint8_t *, size_t);

#endif
