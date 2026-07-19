/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard
 */

#include <string.h>

#include "mesh_lighting.h"

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
