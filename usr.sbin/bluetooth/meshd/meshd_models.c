/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * meshd application-model composition (see meshd_models.h).
 *
 * The single place where the node's application models are initialised and
 * registered onto the sim node's elements.  Model families extend this by
 * appending one registration block per family, guarded by the target element
 * index; the shared scaffolding (aggregate allocation, error handling) stays
 * unchanged.  The simulator capacity deliberately accommodates the complete
 * set of application models registered here.
 */

#include <stdlib.h>

#include "meshd.h"
#include "meshd_models.h"

static void
meshd_primary_level_changed(void *arg, int16_t level)
{
	struct meshd_app_models *app = arg;
	uint16_t actual;

	if (app == NULL || app->binding_busy)
		return;
	app->binding_busy = 1;
	actual = (uint16_t)((int32_t)level + 32768);
	app->lightness.actual = actual;
	app->power_level.actual = actual;
	if (actual != 0) {
		app->lightness.last = actual;
		app->power_level.last = actual;
	}
	mesh_gen_onoff_srv_set_present(&app->onoff, actual != 0);
	app->binding_busy = 0;
}

static void
meshd_primary_onoff_changed(void *arg, uint8_t onoff)
{
	struct meshd_app_models *app = arg;
	uint16_t actual;

	if (app == NULL || app->binding_busy)
		return;
	app->binding_busy = 1;
	if (onoff == MESH_GEN_OFF)
		actual = 0;
	else if (app->lightness.actual != 0)
		actual = app->lightness.actual;
	else if (app->power_level.actual != 0)
		actual = app->power_level.actual;
	else if (app->lightness.last != 0)
		actual = app->lightness.last;
	else
		actual = app->power_level.last;
	app->lightness.actual = actual;
	app->power_level.actual = actual;
	if (actual != 0) {
		app->lightness.last = actual;
		app->power_level.last = actual;
	}
	mesh_gen_level_srv_set_present(&app->level,
	    (int16_t)((int32_t)actual - 32768));
	app->binding_busy = 0;
}

static void
meshd_ctl_level_changed(void *arg, int16_t level)
{
	struct mesh_light_ctl_srv *ctl = arg;
	uint32_t span, scaled;

	if (ctl == NULL)
		return;
	span = (uint32_t)ctl->range_max - ctl->range_min;
	scaled = (uint32_t)((int32_t)level + 32768);
	ctl->temperature = (uint16_t)(ctl->range_min +
	    (scaled * span + UINT32_C(32767)) / UINT32_C(65535));
}

static void
meshd_hue_level_changed(void *arg, int16_t level)
{
	struct mesh_light_hsl_srv *hsl = arg;

	if (hsl != NULL)
		hsl->hue = (uint16_t)((int32_t)level + 32768);
}

static void
meshd_sat_level_changed(void *arg, int16_t level)
{
	struct mesh_light_hsl_srv *hsl = arg;

	if (hsl != NULL)
		hsl->saturation = (uint16_t)((int32_t)level + 32768);
}

static int
meshd_scene_capture(void *arg, uint8_t *out, size_t cap, size_t *outlen)
{
	struct meshd_app_models *app = arg;

	if (app == NULL || out == NULL || outlen == NULL || cap < 5)
		return (-1);
	out[0] = app->onoff.present;
	out[1] = (uint16_t)app->level.present;
	out[2] = (uint16_t)app->level.present >> 8;
	out[3] = app->power_level.actual;
	out[4] = app->power_level.actual >> 8;
	*outlen = 5;
	return (0);
}

static int
meshd_scene_recall(void *arg, const uint8_t *in, size_t len)
{
	struct meshd_app_models *app = arg;
	uint16_t actual;

	if (app == NULL || in == NULL || len != 5 || in[0] > MESH_GEN_ON)
		return (-1);
	mesh_gen_onoff_srv_set_present(&app->onoff, in[0]);
	mesh_gen_level_srv_set_present(&app->level,
	    (int16_t)((uint16_t)in[1] | ((uint16_t)in[2] << 8)));
	actual = (uint16_t)in[3] | ((uint16_t)in[4] << 8);
	mesh_gen_power_level_set_actual(&app->power_level, actual);
	return (0);
}

int
meshd_models_register_all(struct meshd_node *nd, struct mesh_node *node)
{
	struct meshd_app_models *app;

	if (nd == NULL || node == NULL)
		return (-1);

	if (nd->app == NULL) {
		nd->app = calloc(1, sizeof(*nd->app));
		if (nd->app == NULL)
			return (-1);
	}
	app = nd->app;

	/*
	 * Generic OnOff + Generic Level servers on the primary element (0).
	 * State is (re)initialised here so this call is safe on every reprovision.
	 */
	mesh_gen_battery_srv_init(&app->battery);
	mesh_gen_dtt_srv_init(&app->dtt, 0);
	mesh_gen_location_srv_init(&app->location);
	mesh_gen_onoff_srv_init(&app->onoff, MESH_GEN_OFF);
	mesh_gen_level_srv_init(&app->level, 0);
	mesh_gen_level_srv_init(&app->ctl_level, 0);
	mesh_gen_level_srv_init(&app->hue_level, 0);
	mesh_gen_level_srv_init(&app->sat_level, 0);
	app->onoff.dtt = &app->dtt;
	app->level.dtt = &app->dtt;
	app->ctl_level.dtt = &app->dtt;
	app->hue_level.dtt = &app->dtt;
	app->sat_level.dtt = &app->dtt;
	mesh_light_lightness_srv_init(&app->lightness, &app->onoff, &app->level);
	app->lightness.dtt = &app->dtt;
	mesh_light_ctl_srv_init(&app->ctl, &app->lightness);
	mesh_light_hsl_srv_init(&app->hsl, &app->lightness);
	app->ctl.temperature_level = &app->ctl_level;
	app->hsl.hue_level = &app->hue_level;
	app->hsl.saturation_level = &app->sat_level;
	mesh_gen_level_srv_bind(&app->ctl_level, meshd_ctl_level_changed,
	    &app->ctl);
	mesh_gen_level_srv_bind(&app->hue_level, meshd_hue_level_changed,
	    &app->hsl);
	mesh_gen_level_srv_bind(&app->sat_level, meshd_sat_level_changed,
	    &app->hsl);
	mesh_gen_level_srv_set_present(&app->ctl_level, INT16_MIN);
	mesh_gen_level_srv_set_present(&app->hue_level, INT16_MIN);
	mesh_gen_level_srv_set_present(&app->sat_level, INT16_MIN);
	mesh_light_xyl_srv_init(&app->xyl, &app->lightness);
	mesh_light_lc_srv_init(&app->lc, &app->lightness);
	mesh_gen_power_onoff_srv_init(&app->power_onoff, &app->onoff,
	    MESH_GEN_ONPOWERUP_RESTORE);
	mesh_gen_power_level_srv_init(&app->power_level, &app->onoff, &app->level,
	    &app->power_onoff);
	app->power_level.dtt = &app->dtt;
	app->binding_busy = 0;
	mesh_gen_onoff_srv_bind(&app->onoff, meshd_primary_onoff_changed, app);
	mesh_gen_level_srv_bind(&app->level, meshd_primary_level_changed, app);
	mesh_gen_level_srv_set_present(&app->level, INT16_MIN);
	mesh_sensor_srv_init(&app->sensor);
	mesh_scene_srv_init(&app->scene, meshd_scene_capture, meshd_scene_recall,
	    app);
	app->scene.dtt = &app->dtt;
	mesh_scheduler_srv_init(&app->scheduler);
	mesh_time_srv_init(&app->time);
	if (mesh_sim_add_model(node, 0,
	    mesh_gen_battery_srv_model(&app->battery)) != 0)
		return (-1);
	if (mesh_sim_add_model(node, 0, mesh_gen_dtt_srv_model(&app->dtt)) != 0)
		return (-1);
	if (mesh_sim_add_model(node, 0,
	    mesh_gen_location_srv_model(&app->location)) != 0)
		return (-1);
	if (mesh_sim_add_model(node, 0,
	    mesh_gen_location_setup_srv_model(&app->location)) != 0)
		return (-1);
	if (mesh_sim_add_model(node, 0, mesh_gen_onoff_srv_model(&app->onoff)) != 0)
		return (-1);
	if (mesh_sim_add_model(node, 0, mesh_gen_level_srv_model(&app->level)) != 0)
		return (-1);
	if (mesh_sim_add_model(node, 0,
	    mesh_light_lightness_srv_model(&app->lightness)) != 0)
		return (-1);
	if (mesh_sim_add_model(node, 0,
	    mesh_light_lightness_setup_srv_model(&app->lightness)) != 0)
		return (-1);
	if (mesh_sim_add_model(node, 0, mesh_light_ctl_srv_model(&app->ctl)) != 0)
		return (-1);
	if (mesh_sim_add_model(node, 0,
	    mesh_light_ctl_setup_srv_model(&app->ctl)) != 0)
		return (-1);
	if (mesh_sim_add_model(node, 0, mesh_light_hsl_srv_model(&app->hsl)) != 0)
		return (-1);
	if (mesh_sim_add_model(node, 0,
	    mesh_light_hsl_setup_srv_model(&app->hsl)) != 0)
		return (-1);
	if (mesh_sim_add_model(node, 0, mesh_light_xyl_srv_model(&app->xyl)) != 0)
		return (-1);
	if (mesh_sim_add_model(node, 0,
	    mesh_light_xyl_setup_srv_model(&app->xyl)) != 0)
		return (-1);
	if (mesh_sim_add_model(node, 0, mesh_light_lc_srv_model(&app->lc)) != 0)
		return (-1);
	if (mesh_sim_add_model(node, 0,
	    mesh_light_lc_setup_srv_model(&app->lc)) != 0)
		return (-1);
	if (mesh_sim_add_model(node, 0,
	    mesh_gen_power_onoff_srv_model(&app->power_onoff)) != 0)
		return (-1);
	if (mesh_sim_add_model(node, 0,
	    mesh_gen_power_onoff_setup_srv_model(&app->power_onoff)) != 0)
		return (-1);
	if (mesh_sim_add_model(node, 0,
	    mesh_gen_power_level_srv_model(&app->power_level)) != 0)
		return (-1);
	if (mesh_sim_add_model(node, 0,
	    mesh_gen_power_level_setup_srv_model(&app->power_level)) != 0)
		return (-1);
	if (mesh_sim_add_model(node, 0, mesh_sensor_srv_model(&app->sensor)) != 0)
		return (-1);
	if (mesh_sim_add_model(node, 0,
	    mesh_sensor_setup_srv_model(&app->sensor)) != 0)
		return (-1);
	if (mesh_sim_add_model(node, 0, mesh_time_srv_model(&app->time)) != 0)
		return (-1);
	if (mesh_sim_add_model(node, 0,
	    mesh_time_setup_srv_model(&app->time)) != 0)
		return (-1);
	if (mesh_sim_add_model(node, 0, mesh_scene_srv_model(&app->scene)) != 0)
		return (-1);
	if (mesh_sim_add_model(node, 0,
	    mesh_scene_setup_srv_model(&app->scene)) != 0)
		return (-1);
	if (mesh_sim_add_model(node, 0,
	    mesh_scheduler_srv_model(&app->scheduler)) != 0)
		return (-1);
	if (mesh_sim_add_model(node, 0,
	    mesh_scheduler_setup_srv_model(&app->scheduler)) != 0)
		return (-1);
	if (mesh_sim_add_model(node, 1,
	    mesh_gen_level_srv_model(&app->ctl_level)) != 0 ||
	    mesh_sim_add_model(node, 1,
	    mesh_light_ctl_temp_srv_model(&app->ctl)) != 0)
		return (-1);
	if (mesh_sim_add_model(node, 2,
	    mesh_gen_level_srv_model(&app->hue_level)) != 0 ||
	    mesh_sim_add_model(node, 2,
	    mesh_light_hsl_hue_srv_model(&app->hsl)) != 0)
		return (-1);
	if (mesh_sim_add_model(node, 3,
	    mesh_gen_level_srv_model(&app->sat_level)) != 0 ||
	    mesh_sim_add_model(node, 3,
	    mesh_light_hsl_sat_srv_model(&app->hsl)) != 0)
		return (-1);

	/* Families append their registration blocks below. */

	return (0);
}

void
meshd_models_fini(struct meshd_node *nd)
{

	if (nd == NULL)
		return;
	free(nd->app);
	nd->app = NULL;
}
