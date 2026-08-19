/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard
 */

#include <string.h>

#include "mesh_lighting.h"

/*
 * NOTE (LOW): Light LC control is UNIMPLEMENTED here — this file is codec/
 * property storage only.  The Light LC state machine defined by MMDL 6.2.3
 * (the Off / Standby / Fade On / Run / Fade / Prolong / Fade Standby Auto/Manual
 * modes), the PI feedback regulator that computes the Linear Output, and the
 * occupancy/ambient-light sensor inputs that drive those state transitions are
 * NOT present.  The Light LC Mode/OM/Light OnOff codecs and the LC Property
 * table live in mesh_lighting.c/this file, but they do not run the controller.
 * Do not mistake the presence of these codecs for a complete Light LC Server.
 */

int
mesh_light_lc_property_set(struct mesh_light_lc_srv *srv, uint16_t id,
    const uint8_t *value, size_t len)
{
	size_t i;

	if (srv == NULL || id == 0 || (value == NULL && len != 0) ||
	    len > MESH_LIGHT_LC_PROPERTY_VALUE_MAX)
		return (-1);
	for (i = 0; i < srv->n_properties && srv->properties[i].id != id; i++)
		;
	if (i == srv->n_properties) {
		if (i == MESH_LIGHT_LC_MAX_PROPERTIES)
			return (-1);
		srv->n_properties++;
		srv->properties[i].id = id;
	}
	srv->properties[i].len = len;
	if (len != 0)
		memcpy(srv->properties[i].value, value, len);
	return (0);
}
