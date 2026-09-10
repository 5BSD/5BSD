/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

#ifndef _BLUED_CONFIG_H_
#define _BLUED_CONFIG_H_

#include <sys/param.h>
#include <stdbool.h>
#include <stdint.h>

#define BLUED_MAX_DEVICES	16
#define BLUED_MAX_CONF_SERVICES	8
#define BLUED_MAX_CONF_CHARS	8	/* per service */
#define BLUED_MAX_CONF_DESCS	4	/* per characteristic (non-CCCD) */
#define BLUED_MAX_CONF_INCLUDES	4	/* per service */

/* Default paths and tuning constants */
#define BLUED_PIDFILE_DEFAULT		"/var/run/blued.pid"
#define BLUED_BONDDB_DEFAULT		"/var/db/blued/bonds"
#define BLUED_CTLSOCK_DEFAULT		"/var/run/blued.sock"
#define BLUED_CONFIG_DEFAULT		"/etc/blued.conf"
#define BLUED_MIN_KEY_SIZE_DEFAULT	16	/* KNOB-safe */
#define BLUED_MIN_PAIRING_SECURITY_DEFAULT	2 /* SMP_SEC_AUTH: secure default */
#define BLUED_RECONNECT_MAX_DEFAULT	60
/*
 * Default number of EATT bearers requested at connection setup.  Two is what
 * this stack has always asked for; the value is now operator-settable.
 */
#define BLUED_EATT_BEARERS_DEFAULT	2
#define BLUED_RPA_TIMEOUT_DEFAULT	900	/* 15 minutes */

/* LE Secure Connections mode (config `sc`), mirroring the common off/on/only. */
#define BLUED_SC_OFF	0	/* never advertise SC (legacy only) */
#define BLUED_SC_ON	1	/* advertise SC, allow legacy fallback (default) */
#define BLUED_SC_ONLY	2	/* advertise SC, reject legacy pairing */

/*
 * The daemon's getopt(3) option string.  Shared so that main()'s first pass
 * (which only looks for -c and -h) and blued_config_apply_cli() (which applies
 * every override, including on SIGHUP re-application) can never disagree about
 * which options take an argument -- a desync there would make the first pass
 * mistake an option argument for an operand.
 */
#define BLUED_GETOPT_STRING	"a:Bc:df:hH:L:P:prsv"

/*
 * GATT Database Hash wire byte order (config `gatt { database_hash_byte_order
 * = ... }`, blued(8) -H).  These MUST equal the GATT_DB_HASH_ORDER_* codes in
 * gatt.h, which is where the choice is described in full; config.c pins the
 * two with a _Static_assert.  The default is deliberately the BlueZ order:
 * changing it silently invalidates the cached Database Hash of every already
 * deployed Linux peer.  "reversed" is what a SIG qualification run
 * (GATT/SR/GAS/BV-02-C) needs, and the two are mutually exclusive.
 */
#define BLUED_DB_HASH_ORDER_BLUEZ	0
#define BLUED_DB_HASH_ORDER_REVERSED	1
#define BLUED_DB_HASH_ORDER_DEFAULT	BLUED_DB_HASH_ORDER_BLUEZ

/*
 * COMPATIBILITY PROFILE (config `compatibility_profile`, blued(8) -P).
 *
 * Comparing this stack against BlueZ, Zephyr and Apache NimBLE turned up
 * places where "correct by the Bluetooth specification" and "interoperable
 * with a Linux peer" are not the same answer.  They are not defects -- for a
 * defect one side is simply wrong and it gets fixed -- they are genuine
 * ecosystem splits.  Two of them are in blued's own wire path:
 *
 *   database_hash_byte_order  the octet order of the GATT Database Hash
 *                             characteristic.  BlueZ transmits the raw
 *                             AES-CMAC; Zephyr reverses it deliberately to
 *                             pass GATT/SR/GAS/BV-02-C.  See gatt.h.
 *   att_error_selection       which ATT error a denied request gets on an
 *                             unencrypted link.  Core Vol 3 Part C Table 10.2
 *                             selects on whether a key EXISTS for the peer;
 *                             BlueZ selects on the attribute's permission
 *                             bits.  See att_server.c.
 *
 * An operator should not have to know one knob per split.  A profile names an
 * INTENT and sets the whole family coherently; an individual knob still wins
 * over the profile, so a profile can be taken and one thing adjusted.
 *
 *   BLUED_COMPAT_DEFAULT  what blued has always shipped, and what it still
 *                         ships: specification behaviour everywhere it is
 *                         free, and the BlueZ Database Hash order, because
 *                         changing that invalidates the hash cached by every
 *                         already-paired Linux peer.  Upgrading blued must
 *                         not silently change any peer-visible behaviour, so
 *                         this stays the default.
 *   BLUED_COMPAT_SPEC     strict specification conformance: what a SIG
 *                         qualification run wants.  Costs Linux interop on
 *                         the Database Hash.
 *   BLUED_COMPAT_BLUEZ    match BlueZ where BlueZ and the specification
 *                         differ: what a fleet of Linux peers wants.  Costs
 *                         conformance on the ATT error code.
 *
 * The names are the intents, not the versions: "spec" and "bluez" mean the
 * same thing in five years that they mean today, whereas a name minted from a
 * release ("legacy", "modern", "v2") stops being readable the moment the next
 * one lands.
 */
#define BLUED_COMPAT_DEFAULT	0
#define BLUED_COMPAT_SPEC	1
#define BLUED_COMPAT_BLUEZ	2

/*
 * ATT error-code selection for a denied service request on an UNENCRYPTED
 * link (config `gatt { att_error_selection = ... }`).
 *
 * These codes are consumed by att_set_error_selection() in att_server.c,
 * which is where the behaviour and the specification citations live.  They
 * are declared HERE, in the policy header, because config.h is the only
 * header the configuration parser and the ATT server both include: the ATT
 * server must not gain a dependency on the UCL-based parser (many test
 * programs link att_server.c without config.c), so the constants travel here
 * and the setter is defined over there.
 *
 * The default is the specification's Table 10.2 behaviour, which is what the
 * daemon does today and what Zephyr and NimBLE do.
 */
#define BLUED_ATT_ERRSEL_SPEC	0	/* Vol 3 Part C Table 10.2: key state */
#define BLUED_ATT_ERRSEL_BLUEZ	1	/* BlueZ: attribute permission bits */
#define BLUED_ATT_ERRSEL_DEFAULT	BLUED_ATT_ERRSEL_SPEC

/*
 * One bit per profile-governed knob, set when that knob was named
 * INDIVIDUALLY (its own configuration key or its own command-line flag).
 * blued_config_apply_cli() re-applies the saved argv on every SIGHUP, so a
 * flag's bit is re-asserted on every reload and a command-line override
 * cannot be lost to a reload.  A knob whose bit is set is never written by
 * the profile.
 */
#define BLUED_COMPAT_OVR_DB_HASH_ORDER	0x01u
#define BLUED_COMPAT_OVR_ATT_ERRSEL	0x02u

/*
 * Default key-distribution mask 0x0f = SMP_KEY_DIST_ENC|ID|SIGN|LINK, i.e.
 * LTK (EncKey) + IRK (IdKey) + CSRK (SignKey) + BR/EDR Link Key (LinkKey);
 * Core Spec Vol 3 Part H §3.6.1.
 *
 * This MUST agree with smp_seed_policy_defaults() (smp.c), which seeds
 * sc->our_key_dist/their_key_dist on every freshly opened SMP connection: all
 * three smp_conn producers (blued_central.c, blued_peripheral.c setup and
 * late-pairing paths) overwrite that seed with blued_cfg.key_dist, so a
 * narrower default here silently wins and the library seed never reaches the
 * wire.  It previously read 0x0b, which stripped SignKey from every Pairing
 * Request/Response and made the CSRK distribution/restore paths dead code.
 * config.c pins the two with a _Static_assert; the operator-facing token is
 * "sign" (parse_key_dist()).
 */
#define BLUED_KEY_DIST_DEFAULT	0x0f	/* SMP_KEY_DIST_ENC|ID|SIGN|LINK */

/*
 * A non-CCCD characteristic descriptor authored in the config (finding 136).
 * CCCDs are still auto-added from the notify/indicate properties; this covers
 * everything else (e.g. CUD 0x2901, Report Reference 0x2908, ...).
 */
struct blued_desc_conf {
	uint16_t	uuid16;		/* 0 if using uuid128 */
	uint8_t		uuid128[16];
	uint8_t		permissions;	/* ATT_PERM_* flags */
	uint8_t		value[64];
	uint16_t	value_len;
};

struct blued_char_conf {
	uint16_t	uuid16;		/* 0 if using uuid128 */
	uint8_t		uuid128[16];
	uint8_t		properties;	/* GATT_PROP_* flags */
	uint8_t		permissions;	/* ATT_PERM_* flags */
	uint8_t		initial_value[64];
	uint16_t	initial_value_len;
	bool		has_cccd;	/* auto-add CCCD if notify or indicate */
	struct blued_desc_conf descs[BLUED_MAX_CONF_DESCS];
	int		ndescs;
};

/* An included-service declaration authored in the config (finding 136). */
struct blued_include_conf {
	uint16_t	start;		/* included service start handle */
	uint16_t	end;		/* included service end handle */
	uint16_t	uuid16;		/* included service UUID (0 if unknown) */
};

struct blued_service_conf {
	char		name[64];
	uint16_t	uuid16;		/* 0 if using uuid128 */
	uint8_t		uuid128[16];
	struct blued_char_conf chars[BLUED_MAX_CONF_CHARS];
	int		nchars;
	struct blued_include_conf includes[BLUED_MAX_CONF_INCLUDES];
	int		nincludes;
};

struct blued_device_conf {
	uint8_t		addr[6];
	uint8_t		addr_type;
	bool		reconnect;
};

struct blued_config {
	char		pidfile[PATH_MAX];
	char		bonddb[PATH_MAX];
	char		ctlsock[PATH_MAX];
	char		logfile[PATH_MAX];
	int		loglevel;
	bool		daemonize;

	char		adapters[8][16];
	int		nadapters;		/* 0 = auto-detect */

	uint8_t		io_capability;
	bool		bondable;
	uint8_t		sc_mode;		/* BLUED_SC_OFF/ON/ONLY */
	bool		mitm;			/* require MITM in AuthReq */
	bool		keypress;		/* advertise Keypress Notif */
	uint8_t		key_dist;		/* key-distribution mask */
	uint8_t		min_pairing_security;	/* pairing floor: SMP_SEC_*
						 * (none|enc|auth|sc) */

	bool		eatt;
	/*
	 * Number of Enhanced ATT bearers to request at connection setup.
	 * Core Spec Vol 3 Part G Section 5.4 caps a single
	 * L2CAP_CREDIT_BASED_CONNECTION_REQ at five channels; the count
	 * itself is a local policy choice (BlueZ defaults to 1, NimBLE
	 * supports exactly 1, Zephyr's CONFIG_BT_EATT_MAX defaults to 3).
	 * Range 1..ATT_MAX_EATT_BEARERS; out-of-range values are clamped.
	 */
	int		eatt_bearers;
	bool		privacy;
	bool		reconnect;
	bool		auto_connect;		/* reconnect known devices at startup */
	int		reconnect_max_delay;

	int		min_key_size;		/* minimum encryption key size (7-16, default 16) */
	int		rpa_timeout;		/* RPA rotation timeout (1-3600s) */
	int		privacy_mode;		/* 0=network, 1=device (default) */
	int		subrate_factor;		/* reserved, unused (BT 5.3) */
	bool		peripheral_mode;
	bool		scan_mode;

	char		peripheral_name[64];

	/* Database Hash (0x2B2A) wire order: BLUED_DB_HASH_ORDER_* */
	uint8_t		db_hash_byte_order;

	/* Compatibility profile and the knobs it governs. */
	uint8_t		compat_profile;		/* BLUED_COMPAT_* */
	uint8_t		att_error_selection;	/* BLUED_ATT_ERRSEL_* */
	uint32_t	compat_overrides;	/* BLUED_COMPAT_OVR_* */

	struct blued_device_conf devices[BLUED_MAX_DEVICES];
	int		ndevices;

	struct blued_service_conf services[BLUED_MAX_CONF_SERVICES];
	int		nservices;
};

void	blued_config_defaults(struct blued_config *cfg);
int	blued_config_load(struct blued_config *cfg, const char *path);
int	blued_config_load_fd(struct blued_config *cfg, int fd);
void	blued_config_apply_cli(struct blued_config *cfg, int argc, char **argv);

/* Shared GATT property/permission parsing (used by config.c and ctl.c) */
uint8_t	blued_parse_gatt_properties(const char *str);
uint8_t	blued_parse_gatt_permissions(const char *str);
int	blued_parse_uuid(const char *str, uint16_t *uuid16, uint8_t uuid128[16]);
int	blued_parse_db_hash_byte_order(const char *str, uint8_t *order);

/* Human-readable names for the startup/reload log (blued.c). */
const char *blued_compat_profile_name(uint8_t profile);
const char *blued_att_error_selection_name(uint8_t sel);

/*
 * Publish the resolved ATT error-selection mode to the ATT server.  Defined
 * in att_server.c; see the BLUED_ATT_ERRSEL_* comment above for why the
 * declaration lives in this header.
 */
void	att_set_error_selection(uint8_t mode);
int	blued_parse_hex_value(const char *hex, uint8_t *out, size_t maxlen);

#endif /* _BLUED_CONFIG_H_ */
