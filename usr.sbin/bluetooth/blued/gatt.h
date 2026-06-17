/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

#ifndef _BLUED_GATT_H_
#define _BLUED_GATT_H_

#include <stdint.h>
#include "att.h"

/* Maximum discovery results */
#define GATT_MAX_SERVICES	16
#define GATT_MAX_CHARS		64
#define GATT_MAX_DESCS		128

/*
 * Discovered GATT service.
 */
struct gatt_service {
	uint16_t	start_handle;
	uint16_t	end_handle;
	uint16_t	uuid16;		/* 0 if 128-bit UUID */
	uint8_t		uuid128[16];	/* full UUID if not 16-bit */
};

/*
 * Discovered GATT characteristic.
 */
struct gatt_char {
	uint16_t	decl_handle;	/* declaration handle */
	uint16_t	value_handle;	/* value attribute handle */
	uint8_t		properties;	/* GATT_PROP_* flags */
	uint16_t	uuid16;
	uint8_t		uuid128[16];
};

/*
 * Discovered GATT descriptor.
 */
struct gatt_desc {
	uint16_t	handle;
	uint16_t	uuid16;
	uint8_t		uuid128[16];
};

/*
 * GATT discovery result for a single service.
 */
struct gatt_discovery {
	struct gatt_service	service;
	struct gatt_char	chars[GATT_MAX_CHARS];
	int			nchars;
	struct gatt_desc	descs[GATT_MAX_DESCS];
	int			ndescs;
};

/* gatt.c */
int	gatt_discover_primary_services(struct att_conn *ac,
	    struct gatt_service *svcs, int maxsvcs, int *nsvcs);
int	gatt_discover_characteristics(struct att_conn *ac,
	    uint16_t start, uint16_t end,
	    struct gatt_char *chars, int maxchars, int *nchars);
int	gatt_discover_descriptors(struct att_conn *ac,
	    uint16_t start, uint16_t end,
	    struct gatt_desc *descs, int maxdescs, int *ndescs);

#endif /* _BLUED_GATT_H_ */
