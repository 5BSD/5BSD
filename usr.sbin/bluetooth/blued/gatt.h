/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

#ifndef _BLUED_GATT_H_
#define _BLUED_GATT_H_

#include <stdbool.h>
#include <stdint.h>
#include "att.h"

/* Maximum discovery results */
#define GATT_MAX_SERVICES	16
#define GATT_MAX_CHARS		64
#define GATT_MAX_DESCS		128
#define GATT_MAX_INCLUDES	32

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
 * Discovered GATT include declaration.
 */
struct gatt_include {
	uint16_t	handle;		/* handle of the include declaration */
	uint16_t	start_handle;	/* start handle of included service */
	uint16_t	end_handle;	/* end handle of included service */
	uint16_t	uuid16;		/* 0 if 128-bit UUID */
	uint8_t		uuid128[16];	/* valid if uuid16 == 0 */
	bool		has_uuid;	/* true if UUID was resolved */
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

/* GATT Service UUID */
#define GATT_UUID_GATT_SERVICE		0x1801

/* Database Hash characteristic UUID (Core Spec Vol 3 Part G §7.3.1) */
#define GATT_UUID_DATABASE_HASH		0x2B2A

/* gatt.c */
int	gatt_read_database_hash(struct att_conn *ac, uint8_t hash[16]);
int	gatt_discover_primary_services(struct att_conn *ac,
	    struct gatt_service *svcs, int maxsvcs, int *nsvcs);
int	gatt_discover_primary_service_by_uuid(struct att_conn *ac,
	    uint16_t uuid16, struct gatt_service *services,
	    int max_services, int *count);
int	gatt_discover_primary_service_by_uuid128(struct att_conn *ac,
	    const uint8_t uuid128[16], struct gatt_service *services,
	    int max_services, int *count);
int	gatt_discover_secondary_services(struct att_conn *ac,
	    struct gatt_service *services, int max_services, int *count);
int	gatt_discover_includes(struct att_conn *ac,
	    uint16_t start_handle, uint16_t end_handle,
	    struct gatt_include *includes, int max_includes, int *count);
int	gatt_discover_characteristics(struct att_conn *ac,
	    uint16_t start, uint16_t end,
	    struct gatt_char *chars, int maxchars, int *nchars);
int	gatt_discover_descriptors(struct att_conn *ac,
	    uint16_t start, uint16_t end,
	    struct gatt_desc *descs, int maxdescs, int *ndescs);

#endif /* _BLUED_GATT_H_ */
