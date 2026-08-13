/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Operational-state persistence for blued.
 *
 * Persists and restores the daemon's non-secret operational state across a
 * restart: adapter settings, the known-device cache, the per-device GATT
 * cache (Core Spec Vol 3 Part G §2.5.2 robust caching), and the advertising
 * configuration.  Bond keys are NOT handled here -- they live in the
 * encrypted bond database (smp_keys.c).  The device and GATT caches hold only
 * the non-key metadata and reconcile against the bond database by address.
 *
 * Each artifact is written as a self-describing frame:
 *   magic[8] | version | flags | record_size | count | payload_len | crc32
 * followed by count fixed-size records.  Writes are atomic (temp file +
 * fsync + renameat, relative to a pre-opened directory fd so the pattern
 * works inside the Capsicum sandbox).  The state is non-secret, so integrity
 * is provided by a CRC32 over the header and payload rather than encryption.
 *
 * On load every framed field is validated and every count/length is clamped
 * to the caller's buffer before use, so a truncated, corrupt, wrong-magic,
 * unknown-version, or hostile file is rejected and the daemon falls back to
 * defaults instead of trusting poisoned state.
 */

#ifndef _BLUED_PERSIST_H_
#define _BLUED_PERSIST_H_

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>

/* Default directory for persisted state (0700, files 0600). */
#define BLUED_PERSIST_DIR_DEFAULT	"/var/db/blued"

/* On-disk file names within the persist directory. */
#define BLUED_PERSIST_SETTINGS_FILE	"settings"
#define BLUED_PERSIST_DEVCACHE_FILE	"devcache"
#define BLUED_PERSIST_GATTCACHE_FILE	"gattcache"
#define BLUED_PERSIST_ADVCONFIG_FILE	"advconfig"

/* Frame header size in bytes (see blued_persist.c for the field layout). */
#define BLUED_PERSIST_HDR_SIZE		28

/* Upper bound on any single artifact payload (defensive load cap). */
#define BLUED_PERSIST_MAX_PAYLOAD	(1024u * 1024u)

/* ================================================================
 * Artifact 1: adapter settings (single record).
 * ================================================================ */
#define BLUED_PERSIST_SETTINGS_MAGIC	"BLUEDSET"
/*
 * v1 = initial format; v2 adds default connection parameters + rpa_timeout;
 * v4 adds the preferred ATT MTU (finding 140).
 */
#define BLUED_PERSIST_SETTINGS_VERSION	4

struct blued_persist_settings {
	char		name[64];		/* local device name */
	uint8_t		privacy;		/* privacy/RPA enabled */
	uint8_t		privacy_mode;		/* 0=network, 1=device */
	uint8_t		discoverable;		/* runtime discoverable state */
	uint8_t		connectable;		/* runtime connectable state */
	uint8_t		io_capability;
	uint8_t		bondable;
	uint8_t		sc_mode;
	uint8_t		_pad0;
	int32_t		min_key_size;		/* negotiated key-size floor */
	/* --- fields below appended in v2 --- */
	uint16_t	conn_interval_min;	/* default, units of 1.25ms */
	uint16_t	conn_interval_max;
	uint16_t	conn_latency;
	uint16_t	supervision_timeout;	/* units of 10ms */
	int32_t		rpa_timeout;		/* RPA rotation timeout (s) */
	/* --- fields below appended in v4 (finding 140) --- */
	uint16_t	preferred_mtu;		/* preferred ATT MTU, 0 = default */
	uint16_t	_pad1;
};

/* ================================================================
 * Artifact 2: known-device cache.
 * ================================================================ */
#define BLUED_PERSIST_DEVCACHE_MAGIC	"BLUEDDEV"
/* v1 = initial format; v2 adds appearance + is_hogp. */
#define BLUED_PERSIST_DEVCACHE_VERSION	2
#define BLUED_PERSIST_MAX_DEVICES	64

struct blued_persist_device {
	uint8_t		addr[6];		/* last-seen address */
	uint8_t		addr_type;		/* BDADDR_LE_* */
	uint8_t		has_identity;		/* identity_addr valid (RPA resolved) */
	uint8_t		identity_addr[6];
	uint8_t		identity_addr_type;
	uint8_t		has_name;
	char		name[32];		/* GAP Device Name 0x2A00 */
	uint8_t		auto_connect;		/* reconnect policy */
	uint8_t		bonded;			/* a bond exists for this device */
	uint8_t		_pad0;
	uint8_t		_pad1;
	int64_t		last_seen;		/* unix time, 0 if unknown */
	/* --- fields below appended in v2 --- */
	uint16_t	appearance;		/* GAP Appearance 0x2A01 */
	uint8_t		has_appearance;
	uint8_t		is_hogp;		/* device is a HID-over-GATT peer */
};

/* ================================================================
 * Artifact 3: per-device GATT cache (robust caching across restart).
 * ================================================================ */
#define BLUED_PERSIST_GATTCACHE_MAGIC	"BLUEDGAT"
#define BLUED_PERSIST_GATTCACHE_VERSION	1
#define BLUED_PERSIST_MAX_GATT_DEVICES	32
#define BLUED_PERSIST_MAX_GATT_ATTRS	64

/* Attribute kinds recorded in the cache. */
#define BLUED_PERSIST_ATTR_SERVICE	1
#define BLUED_PERSIST_ATTR_CHAR		2
#define BLUED_PERSIST_ATTR_DESC		3

struct blued_persist_gatt_attr {
	uint16_t	handle;
	uint16_t	group_end;		/* service/char group end handle */
	uint16_t	value_handle;		/* characteristic value handle */
	uint16_t	uuid16;			/* 0 if uuid128 is used */
	uint8_t		uuid128[16];
	uint8_t		type;			/* BLUED_PERSIST_ATTR_* */
	uint8_t		properties;		/* GATT characteristic properties */
	uint8_t		_pad0;
	uint8_t		_pad1;
};

struct blued_persist_gatt_device {
	uint8_t		addr[6];
	uint8_t		addr_type;
	uint8_t		has_db_hash;
	uint8_t		db_hash[16];		/* GATT Database Hash (0x2B2A) */
	uint16_t	nattrs;
	uint16_t	_pad0;
	struct blued_persist_gatt_attr attrs[BLUED_PERSIST_MAX_GATT_ATTRS];
};

/* ================================================================
 * Artifact 4: advertising configuration.
 * ================================================================ */
#define BLUED_PERSIST_ADVCONFIG_MAGIC	"BLUEDADV"
#define BLUED_PERSIST_ADVCONFIG_VERSION	1
#define BLUED_PERSIST_MAX_ADV_SETS	4

struct blued_persist_adv_set {
	uint8_t		handle;			/* advertising set handle */
	uint8_t		enabled;
	uint8_t		own_addr_type;
	uint8_t		adv_data_len;
	uint8_t		scan_rsp_len;
	uint8_t		_pad0;
	uint16_t	adv_props;		/* connectable/scannable/legacy */
	uint16_t	interval_min;		/* units of 0.625ms */
	uint16_t	interval_max;
	uint8_t		adv_data[31];
	uint8_t		scan_rsp[31];
	uint8_t		_pad1;
	uint8_t		_pad2;
};

/* ================================================================
 * Generic framed record engine.
 *
 * Both operate relative to a directory fd (dirfd) using *at() syscalls so
 * they are usable after cap_enter().  save writes atomically (temp + fsync +
 * renameat).  load validates magic, requires the exact current version and
 * record size, verifies the CRC and exact file length, and clamps count to
 * max_count.  load returns 0 and fills the count_out/version_out arguments on
 * a good file; -1 (with count_out set to 0) when the file is missing, corrupt,
 * or
 * untrusted -- the caller then uses defaults.
 * ================================================================ */
int	blued_persist_save_records(int dirfd, const char *name,
	    const char *magic, uint16_t version, uint32_t record_size,
	    uint32_t count, const void *records);
int	blued_persist_load_records(int dirfd, const char *name,
	    const char *magic, uint16_t current_version,
	    uint32_t current_record_size,
	    uint32_t max_count, void *records_out, uint32_t *count_out,
	    uint16_t *version_out);

/* ================================================================
 * Typed artifact wrappers.  Each returns 0 on a successful round trip and
 * -1 when the file is absent/corrupt (caller keeps its defaults).
 * ================================================================ */
int	blued_persist_settings_save(int dirfd,
	    const struct blued_persist_settings *s);
int	blued_persist_settings_load(int dirfd,
	    struct blued_persist_settings *s);

int	blued_persist_devcache_save(int dirfd,
	    const struct blued_persist_device *devs, uint32_t ndevs);
int	blued_persist_devcache_load(int dirfd,
	    struct blued_persist_device *devs, uint32_t *ndevs);

int	blued_persist_gattcache_save(int dirfd,
	    const struct blued_persist_gatt_device *devs, uint32_t ndevs);
int	blued_persist_gattcache_load(int dirfd,
	    struct blued_persist_gatt_device *devs, uint32_t *ndevs);

int	blued_persist_advconfig_save(int dirfd,
	    const struct blued_persist_adv_set *sets, uint32_t nsets);
int	blued_persist_advconfig_load(int dirfd,
	    struct blued_persist_adv_set *sets, uint32_t *nsets);

/* ================================================================
 * Helpers.
 * ================================================================ */

/*
 * Open (creating if needed, mode 0700) the persist directory and return a
 * directory fd suitable for the *_save/_load calls, or -1 on failure.
 */
int	blued_persist_open_dir(const char *path);

/*
 * GATT robust-caching decision (Core Spec Vol 3 Part G §2.5.2): true when the
 * cached device carries a Database Hash equal to the freshly read one, so the
 * cached handles may be reused and rediscovery skipped.  A mismatch (or an
 * absent stored hash) returns false, meaning the cache must be invalidated and
 * the database rediscovered.
 */
bool	blued_persist_gatt_hash_matches(
	    const struct blued_persist_gatt_device *d,
	    const uint8_t db_hash[16]);

/*
 * Find a cached device / GATT device by address+type; NULL if absent.
 */
struct blued_persist_device *blued_persist_devcache_find(
	    struct blued_persist_device *devs, uint32_t ndevs,
	    const uint8_t addr[6], uint8_t addr_type);
struct blued_persist_gatt_device *blued_persist_gattcache_find(
	    struct blued_persist_gatt_device *devs, uint32_t ndevs,
	    const uint8_t addr[6], uint8_t addr_type);

/* CRC32 (IEEE, reflected) over buf; seed with 0 for a fresh checksum. */
uint32_t blued_persist_crc32(uint32_t crc, const void *buf, size_t len);

#endif /* _BLUED_PERSIST_H_ */
