/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * meshd application-model composition.
 *
 * This is the single serialisation point for the node's application models.
 * Rather than embedding every per-model server/client state by value in
 * struct meshd_node (which would make every new model family a merge conflict
 * in meshd.h and grow the node value size), all model state lives in one
 * heap-allocated aggregate, struct meshd_app_models, reached through
 * meshd_node.app.  A new model family appends exactly one struct member below
 * (kept alphabetical) and one registration block in meshd_models_register_all()
 * (meshd_models.c); nothing else in the node struct changes.
 *
 * meshd_models_register_all() is the composition entry point: it (re)initialises
 * each model's state and registers its access-layer factory (server + setup +
 * client) onto the correct element index of the freshly built mesh_node.  It is
 * invoked from meshd_setup_node() on every (re)provision, so it must be
 * idempotent with respect to the aggregate (it re-inits state each call).
 */

#ifndef _MESHD_MODELS_H_
#define _MESHD_MODELS_H_

#include "mesh_generic.h"
#include "mesh_sensor.h"
#include "mesh_lighting.h"
#include "mesh_time_scene.h"

struct meshd_node;
struct mesh_node;

/*
 * Aggregate of every application model's server/client state, heap-allocated
 * once per node (meshd_node.app) and freed in meshd_node_fini().  Model
 * families append their sub-structs here, one line each, alphabetically.
 * Intra-node state binding (e.g. Generic Power OnOff -> Generic OnOff, or the
 * Light component models -> Light Lightness) is expressed as pointers between
 * these co-located members, set up in meshd_models_register_all().
 */
struct meshd_app_models {
	struct mesh_gen_battery_srv	battery;	/* Generic Battery (0x100c) */
	struct mesh_gen_dtt_srv		dtt;	/* Default Transition Time (0x1004) */
	struct mesh_gen_onoff_srv	onoff;	/* Generic OnOff Server  (0x1000) */
	struct mesh_gen_level_srv	level;	/* Generic Level Server  (0x1002) */
	struct mesh_gen_level_srv	ctl_level; /* CTL Temperature binding */
	struct mesh_gen_level_srv	hue_level; /* HSL Hue binding */
	struct mesh_gen_level_srv	sat_level; /* HSL Saturation binding */
	struct mesh_light_lightness_srv lightness; /* Light Lightness + Setup */
	struct mesh_light_lc_srv	lc;	/* Light LC + Setup */
	struct mesh_light_ctl_srv	ctl;	/* Light CTL + Setup */
	struct mesh_light_hsl_srv	hsl;	/* Light HSL + Setup/Hue/Saturation */
	struct mesh_light_xyl_srv	xyl;	/* Light xyL + Setup */
	struct mesh_gen_location_srv	location; /* Location Server + Setup */
	struct mesh_gen_power_onoff_srv power_onoff; /* Server + Setup (0x1006/7) */
	struct mesh_gen_power_level_srv power_level; /* Server + Setup (0x1009/a) */
	struct mesh_sensor_srv		sensor;	/* Sensor Server + Setup (0x1100/1) */
	struct mesh_scene_srv		scene;	/* Scene Server + Setup (0x1203/4) */
	struct mesh_scheduler_srv	scheduler; /* Scheduler Server + Setup */
	struct mesh_time_srv		time;	/* Time Server + Setup (0x1200/1) */
	int				binding_busy;
	/* Families append their state here, alphabetically, one line each. */
};

/*
 * Initialise every application model and register its access-layer factories
 * onto node's elements.  Lazily allocates nd->app on first call.  Returns 0 on
 * success, -1 on allocation failure or if a model list overflows.
 */
int	meshd_models_register_all(struct meshd_node *nd, struct mesh_node *node);

/* Release nd->app (safe on a NULL aggregate). */
void	meshd_models_fini(struct meshd_node *nd);

#endif /* _MESHD_MODELS_H_ */
