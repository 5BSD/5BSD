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

/*
 * Database Hash (0x2B2A) WIRE byte order.
 *
 * The hash itself is AES-CMAC(k=0, m) over the attribute concatenation
 * (Core Spec Vol 3 Part G §7.3.1); attdb_compute_db_hash() returns that raw
 * MAC output most significant octet first, which is how Appendix B prints it
 * (F1 CA 2D ... A9 90).  The specification does NOT unambiguously state the
 * order in which those 16 octets are transmitted in the characteristic value,
 * and the ecosystem is genuinely split:
 *
 *   GATT_DB_HASH_ORDER_BLUEZ    transmit the raw CMAC output unreversed.
 *     BlueZ src/shared/crypto.c bt_crypto_gatt_hash() performs no swap (unlike
 *     its SMP aes_cmac() path, which does), and src/gatt-database.c
 *     db_hash_read_cb() places those octets straight into the ATT Read
 *     Response; src/shared/gatt-client.c compares a peer's value unreversed.
 *     Reading (a) of the spec: §7.3.1 and Appendix B define the hash as an
 *     octet string printed most significant octet first, so transmit it so.
 *
 *   GATT_DB_HASH_ORDER_REVERSED transmit the same 128-bit value least
 *     significant octet first.  Zephyr does this deliberately
 *     (subsys/bluetooth/host/gatt.c db_hash_gen() calls sys_mem_swap() with a
 *     comment naming PTS), because Table 7.8 types the value uint128 and
 *     Vol 3 Part G §2.4 makes characteristic values little-endian unless
 *     otherwise defined.  This is what the SIG qualification test
 *     GATT/SR/GAS/BV-02-C expects.
 *
 * The two are mutually exclusive on the wire, so blued makes the choice an
 * operator knob (blued.conf `gatt { database_hash_byte_order = ... }`,
 * blued(8) -H) and defaults to the BlueZ order, which is what every already
 * deployed Linux peer of this daemon has cached.
 *
 * INTERNAL REPRESENTATION: everything inside blued -- the value returned by
 * attdb_compute_db_hash(), the hash stored in a bond record and persisted to
 * the bond database (struct smp_bond::db_hash, struct blued_persist_gatt::
 * db_hash), and the value returned by gatt_read_database_hash() -- is in
 * COMPUTATION order (raw CMAC, most significant octet first), independent of
 * the configured wire order.  Only the four wire boundaries convert.  A bond
 * database therefore stays valid when the knob is flipped, and a stored hash
 * may be compared byte-for-byte with a freshly computed one.
 */
#define GATT_DB_HASH_ORDER_BLUEZ	0	/* raw CMAC, MSB first */
#define GATT_DB_HASH_ORDER_REVERSED	1	/* LSB first (Zephyr/PTS) */
#define GATT_DB_HASH_LEN		16

/* Service Changed characteristic UUID (Core Spec Vol 3 Part G §7.1) */
#define GATT_UUID_SERVICE_CHANGED	0x2A05

/* Client Characteristic Configuration descriptor, Core Vol 3 Part G §3.3.3.3 */
#define GATT_UUID_CCCD_DESC		0x2902

/* Characteristic declaration (Core Vol 3 Part G §3.3.1) */
#define GATT_UUID_CHAR_DECL		0x2803

/*
 * Client Supported Features characteristic (Core Spec Vol 3 Part G §7.2).
 * Table 7.6 assigns octet 0 bit 0 to Robust Caching, bit 1 to EATT and bit 2
 * to Multiple Handle Value Notifications.
 *
 * Two rules bound any write to it (§7.2 lines 75093-75100): for a bonded
 * client the value is persistent across connections, and "A client shall not
 * clear any bits it has set.  The server shall respond to any such request
 * with the Error Code parameter set to Value Not Allowed (0x13)."  So the
 * value is read, OR-ed, and written back only when it actually changes.
 */
#define GATT_UUID_CLIENT_SUPP_FEAT	0x2B29
#define GATT_CSF_ROBUST_CACHING		0x01
#define GATT_CSF_EATT			0x02
#define GATT_CSF_MULTI_NOTIFY		0x04

/* CCCD value bits (Core Spec Vol 3 Part G Table 3.11). */
#define GATT_CCCD_NOTIFICATION		0x0001
#define GATT_CCCD_INDICATION		0x0002

/*
 * A received Handle Value Indication is a Service Changed indication only if
 * it targets the Service Changed characteristic's value handle (recorded at
 * discovery) AND carries the 4-octet {affected start, affected end} range.
 * Core Spec Vol 3 Part G §2.5.2 identifies Service Changed by the
 * characteristic — i.e. its value handle — not by PDU length; matching on the
 * 4-byte length alone lets ANY 4-byte indication on ANY handle thrash the
 * cached GATT handle set.  A zero recorded handle (characteristic absent or
 * not yet discovered) never matches.
 */
static inline bool
gatt_indication_is_service_changed(uint16_t svc_changed_value_handle,
    uint16_t ind_handle, size_t ind_len)
{
	return (svc_changed_value_handle != 0 &&
	    ind_handle == svc_changed_value_handle && ind_len == 4);
}

/* gatt.c */
void	gatt_set_db_hash_byte_order(uint8_t order);
uint8_t	gatt_get_db_hash_byte_order(void);
void	gatt_db_hash_to_wire(const uint8_t hash[GATT_DB_HASH_LEN],
	    uint8_t wire[GATT_DB_HASH_LEN]);
void	gatt_db_hash_from_wire(const uint8_t wire[GATT_DB_HASH_LEN],
	    uint8_t hash[GATT_DB_HASH_LEN]);
/*
 * Recompute the Database Hash over db and rewrite the 0x2B2A characteristic
 * value with it, converted to the configured wire byte order.  This is the
 * single publish primitive: peripheral_build_gattdb() calls it once the
 * database is complete, and ctl_gatt.c calls it after every live structural
 * change.  Callers must hold blued_g.gatt_db_lock when db is the daemon's
 * shared peripheral database.
 */
void	gatt_db_publish_hash(struct att_db *db);
int	gatt_read_database_hash(struct att_conn *ac, uint8_t hash[16]);
int	gatt_set_client_supported_features(struct att_conn *ac, uint8_t bits);
int	gatt_find_cccd(struct att_conn *ac, uint16_t value_handle,
	    uint16_t search_end, uint16_t *cccd_handle);
int	gatt_write_cccd(struct att_conn *ac, uint16_t cccd_handle,
	    uint16_t value);
int	gatt_discover_primary_services(struct att_conn *ac,
	    struct gatt_service *svcs, int maxsvcs, int *nsvcs);
int	gatt_discover_primary_services_range(struct att_conn *ac,
	    uint16_t start_handle, uint16_t end_handle,
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
