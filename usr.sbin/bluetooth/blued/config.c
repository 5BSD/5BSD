/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * UCL configuration file parser for blued.
 *
 * Config file format (UCL):
 *
 *   general {
 *       pidfile = "/var/run/blued.pid";
 *       bonddb = "/var/db/blued/bonds";
 *       ctlsock = "/var/run/blued.sock";
 *       logfile = "/var/log/blued.btsnoop";
 *       loglevel = 1;
 *       daemonize = true;
 *   }
 *
 *   adapters = ["ubt0", "ubt1"];
 *
 *   security {
 *       io_capability = "keyboard_display";
 *       bondable = true;
 *       sc = "on";
 *   }
 *
 *   features {
 *       eatt = true;
 *       privacy = true;
 *       reconnect = true;
 *       reconnect_max_delay = 60;
 *   }
 *
 *   devices {
 *       "aa:bb:cc:dd:ee:ff" {
 *           type = "random";
 *           reconnect = true;
 *       }
 *   }
 */

#include <sys/param.h>
#include <sys/stat.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ucl.h>

#include "att.h"
#include "att_server.h"
#include "config.h"
#include "smp.h"
#include "ble_util.h"
#include "hci_log.h"

void
blued_config_defaults(struct blued_config *cfg)
{

	memset(cfg, 0, sizeof(*cfg));
	strlcpy(cfg->pidfile, BLUED_PIDFILE_DEFAULT, sizeof(cfg->pidfile));
	strlcpy(cfg->bonddb, BLUED_BONDDB_DEFAULT, sizeof(cfg->bonddb));
	strlcpy(cfg->ctlsock, BLUED_CTLSOCK_DEFAULT, sizeof(cfg->ctlsock));
	cfg->logfile[0] = '\0';
	cfg->loglevel = 0;
	cfg->daemonize = false;
	cfg->nadapters = 0;		/* auto-detect */

	cfg->io_capability = SMP_IO_KEYBOARD_DISPLAY;
	cfg->bondable = true;
	cfg->sc_mode = BLUED_SC_ON;	/* advertise SC, allow legacy (prior behaviour) */
	/*
	 * De-hardcoded AuthReq / key-distribution policy defaults, set to the
	 * exact values the SMP handshake previously baked in as literals so the
	 * daemon's on-the-wire behaviour is unchanged unless an operator sets
	 * one of these keys.
	 */
	cfg->mitm = true;
	cfg->keypress = true;
	cfg->key_dist = BLUED_KEY_DIST_DEFAULT;
	/*
	 * Secure-by-default: require MITM-authenticated pairing.  A
	 * connection whose smp_conn floor is left at SMP_SEC_NONE (e.g. unit
	 * tests that build an smp_conn directly) still pairs freely; the daemon
	 * copies this authenticated floor onto every live pairing.
	 */
	cfg->min_pairing_security = SMP_SEC_AUTH;

	cfg->eatt = true;
	cfg->privacy = true;
	cfg->reconnect = true;
	cfg->auto_connect = true;
	cfg->reconnect_max_delay = BLUED_RECONNECT_MAX_DEFAULT;

	cfg->min_key_size = BLUED_MIN_KEY_SIZE_DEFAULT;
	cfg->rpa_timeout = BLUED_RPA_TIMEOUT_DEFAULT;
	cfg->privacy_mode = 1;			/* device privacy (default) */
	cfg->subrate_factor = 0;		/* disabled by default */

	cfg->peripheral_mode = false;
	cfg->scan_mode = false;
	strlcpy(cfg->peripheral_name, "FreeBSD-BLE",
	    sizeof(cfg->peripheral_name));
	cfg->ndevices = 0;
}

/*
 * Parse an IO capability string to its SMP constant.
 */
static uint8_t
parse_io_capability(const char *str)
{

	if (strcmp(str, "display_only") == 0)
		return (SMP_IO_DISPLAY_ONLY);
	if (strcmp(str, "display_yesno") == 0)
		return (SMP_IO_DISPLAY_YESNO);
	if (strcmp(str, "keyboard_only") == 0)
		return (SMP_IO_KEYBOARD_ONLY);
	if (strcmp(str, "no_input_no_output") == 0 ||
	    strcmp(str, "none") == 0)
		return (SMP_IO_NO_INPUT_NO_OUTPUT);
	if (strcmp(str, "keyboard_display") == 0)
		return (SMP_IO_KEYBOARD_DISPLAY);
	fprintf(stderr, "blued: unknown io_capability '%s', "
	    "using keyboard_display\n", str);
	return (SMP_IO_KEYBOARD_DISPLAY);
}

/*
 * Parse a minimum-security-for-pairing policy string to its SMP_SEC_* level.
 * An unrecognized value falls back to the secure "auth" default rather
 * than silently weakening the floor.
 */
static uint8_t
parse_min_pairing_security(const char *str)
{

	if (strcmp(str, "none") == 0)
		return (SMP_SEC_NONE);
	if (strcmp(str, "enc") == 0)
		return (SMP_SEC_ENC);
	if (strcmp(str, "auth") == 0)
		return (SMP_SEC_AUTH);
	if (strcmp(str, "sc") == 0)
		return (SMP_SEC_SC);
	fprintf(stderr, "blued: unknown min_pairing_security '%s', "
	    "using auth\n", str);
	return (SMP_SEC_AUTH);
}

/*
 * Parse an LE Secure Connections mode string (off/on/only), mirroring the
 * common SecureConnections tri-state.  Unknown values keep SC advertised with
 * legacy fallback (the historical behaviour).
 */
static uint8_t
parse_sc_mode(const char *str)
{

	if (strcmp(str, "off") == 0)
		return (BLUED_SC_OFF);
	if (strcmp(str, "on") == 0)
		return (BLUED_SC_ON);
	if (strcmp(str, "only") == 0)
		return (BLUED_SC_ONLY);
	fprintf(stderr, "blued: unknown sc mode '%s', using on\n", str);
	return (BLUED_SC_ON);
}

/*
 * Parse a key-distribution mask string, a comma/plus/space list of the tokens
 * enc, id, link, and legacy sign.  An
 * empty or "none" list distributes no keys.  Unknown tokens are ignored.
 */
static uint8_t
parse_key_dist(const char *str)
{
	char buf[256];
	char *token, *saveptr;
	uint8_t mask = 0;

	if (str == NULL || strlcpy(buf, str, sizeof(buf)) >= sizeof(buf))
		return (0);
	for (token = strtok_r(buf, ",+ \t", &saveptr); token != NULL;
	    token = strtok_r(NULL, ",+ \t", &saveptr)) {
		if (strcmp(token, "enc") == 0)
			mask |= SMP_KEY_DIST_ENC_KEY;
		else if (strcmp(token, "id") == 0)
			mask |= SMP_KEY_DIST_ID_KEY;
		else if (strcmp(token, "link") == 0)
			mask |= SMP_KEY_DIST_LINK_KEY;
		/* Removed in Core 5.1; accepted only for legacy peers/configs. */
		else if (strcmp(token, "sign") == 0)
			mask |= SMP_KEY_DIST_LEGACY_SIGN_KEY;
	}
	return (mask);
}

/*
 * Parse an address type string.
 */
static uint8_t
parse_addr_type(const char *str)
{

	if (strcmp(str, "random") == 0)
		return (BDADDR_LE_RANDOM);
	return (BDADDR_LE_PUBLIC);
}

/*
 * Parse the "devices" array from the UCL config.
 */
static void
config_parse_device(struct blued_config *cfg, const ucl_object_t *obj,
    const char *key)
{
	const ucl_object_t *val;
	struct blued_device_conf *d;
	const char *addr;

	if (cfg->ndevices >= BLUED_MAX_DEVICES ||
	    ucl_object_type(obj) != UCL_OBJECT)
		return;

	d = &cfg->devices[cfg->ndevices];
	memset(d, 0, sizeof(*d));
	d->addr_type = BDADDR_LE_PUBLIC;
	d->reconnect = cfg->reconnect;

	val = ucl_object_lookup(obj, "addr");
	if (val != NULL && ucl_object_type(val) == UCL_STRING)
		addr = ucl_object_tostring(val);
	else
		addr = key;
	if (addr == NULL || !bt_aton(addr, (bdaddr_t *)d->addr))
		return;

	val = ucl_object_lookup(obj, "addr_type");
	if (val == NULL)
		val = ucl_object_lookup(obj, "type");
	if (val != NULL && ucl_object_type(val) == UCL_STRING)
		d->addr_type = parse_addr_type(ucl_object_tostring(val));

	val = ucl_object_lookup(obj, "reconnect");
	if (val != NULL && ucl_object_type(val) == UCL_BOOLEAN)
		d->reconnect = ucl_object_toboolean(val);

	cfg->ndevices++;
}

/*
 * Parse:
 *   devices { "aa:bb:cc:dd:ee:ff" { ... } }
 */
static void
config_parse_devices(struct blued_config *cfg, const ucl_object_t *obj)
{
	ucl_object_iter_t it;
	const ucl_object_t *cur;

	it = ucl_object_iterate_new(obj);
	while ((cur = ucl_object_iterate_safe(it, true)) != NULL) {
		if (cfg->ndevices >= BLUED_MAX_DEVICES)
			break;
		config_parse_device(cfg, cur,
		    ucl_object_type(obj) == UCL_OBJECT ?
		    ucl_object_key(cur) : NULL);
	}
	ucl_object_iterate_free(it);
}

/*
 * Parse the "security" section.
 */
static void
config_parse_security(struct blued_config *cfg, const ucl_object_t *obj)
{
	const ucl_object_t *val;

	val = ucl_object_lookup(obj, "io_capability");
	if (val != NULL && ucl_object_type(val) == UCL_STRING)
		cfg->io_capability = parse_io_capability(
		    ucl_object_tostring(val));

	val = ucl_object_lookup(obj, "bondable");
	if (val != NULL && ucl_object_type(val) == UCL_BOOLEAN)
		cfg->bondable = ucl_object_toboolean(val);

	/* Secure Connections policy: off, on, or only. */
	val = ucl_object_lookup(obj, "sc");
	if (val != NULL && ucl_object_type(val) == UCL_STRING)
		cfg->sc_mode = parse_sc_mode(ucl_object_tostring(val));

	val = ucl_object_lookup(obj, "mitm");
	if (val != NULL && ucl_object_type(val) == UCL_BOOLEAN)
		cfg->mitm = ucl_object_toboolean(val);

	val = ucl_object_lookup(obj, "keypress");
	if (val != NULL && ucl_object_type(val) == UCL_BOOLEAN)
		cfg->keypress = ucl_object_toboolean(val);

	/* key_dist / key_distribution: enc,id,sign list or "none". */
	val = ucl_object_lookup(obj, "key_dist");
	if (val == NULL)
		val = ucl_object_lookup(obj, "key_distribution");
	if (val != NULL && ucl_object_type(val) == UCL_STRING)
		cfg->key_dist = parse_key_dist(ucl_object_tostring(val));

	val = ucl_object_lookup(obj, "min_key_size");
	if (val != NULL && ucl_object_type(val) == UCL_INT)
		cfg->min_key_size = MAX(7,
		    MIN((int)ucl_object_toint(val), 16));

	val = ucl_object_lookup(obj, "min_pairing_security");
	if (val != NULL && ucl_object_type(val) == UCL_STRING)
		cfg->min_pairing_security = parse_min_pairing_security(
		    ucl_object_tostring(val));

}

static void
config_parse_general(struct blued_config *cfg, const ucl_object_t *root)
{
	const ucl_object_t *obj;

	obj = ucl_object_lookup(root, "pidfile");
	if (obj != NULL && ucl_object_type(obj) == UCL_STRING)
		strlcpy(cfg->pidfile, ucl_object_tostring(obj),
		    sizeof(cfg->pidfile));

	obj = ucl_object_lookup(root, "bonddb");
	if (obj != NULL && ucl_object_type(obj) == UCL_STRING)
		strlcpy(cfg->bonddb, ucl_object_tostring(obj),
		    sizeof(cfg->bonddb));

	obj = ucl_object_lookup(root, "ctlsock");
	if (obj != NULL && ucl_object_type(obj) == UCL_STRING)
		strlcpy(cfg->ctlsock, ucl_object_tostring(obj),
		    sizeof(cfg->ctlsock));

	obj = ucl_object_lookup(root, "logfile");
	if (obj != NULL && ucl_object_type(obj) == UCL_STRING)
		strlcpy(cfg->logfile, ucl_object_tostring(obj),
		    sizeof(cfg->logfile));

	obj = ucl_object_lookup(root, "loglevel");
	if (obj != NULL && ucl_object_type(obj) == UCL_INT)
		cfg->loglevel = MAX(0, MIN((int)ucl_object_toint(obj), 5));

	obj = ucl_object_lookup(root, "daemonize");
	if (obj != NULL && ucl_object_type(obj) == UCL_BOOLEAN)
		cfg->daemonize = ucl_object_toboolean(obj);

	obj = ucl_object_lookup(root, "peripheral_name");
	if (obj != NULL && ucl_object_type(obj) == UCL_STRING)
		strlcpy(cfg->peripheral_name, ucl_object_tostring(obj),
		    sizeof(cfg->peripheral_name));
}

static void
config_parse_features(struct blued_config *cfg, const ucl_object_t *root)
{
	const ucl_object_t *obj;

	obj = ucl_object_lookup(root, "eatt");
	if (obj != NULL && ucl_object_type(obj) == UCL_BOOLEAN)
		cfg->eatt = ucl_object_toboolean(obj);

	obj = ucl_object_lookup(root, "privacy");
	if (obj != NULL && ucl_object_type(obj) == UCL_BOOLEAN)
		cfg->privacy = ucl_object_toboolean(obj);

	obj = ucl_object_lookup(root, "reconnect");
	if (obj != NULL && ucl_object_type(obj) == UCL_BOOLEAN)
		cfg->reconnect = ucl_object_toboolean(obj);

	obj = ucl_object_lookup(root, "reconnect_max_delay");
	if (obj != NULL && ucl_object_type(obj) == UCL_INT)
		cfg->reconnect_max_delay = MAX(1,
		    MIN((int)ucl_object_toint(obj), 3600));

	obj = ucl_object_lookup(root, "auto_connect");
	if (obj != NULL && ucl_object_type(obj) == UCL_BOOLEAN)
		cfg->auto_connect = ucl_object_toboolean(obj);

	/*
	 * auto_connect_max_tries removed (finding 97): the reconnect retry
	 * budget was parsed and clamped but never consulted by the reconnect
	 * path, so it was a silent no-op.  Rather than keep a misleading knob,
	 * the field is gone; an unbounded retry is still bounded by the
	 * reconnect_max_delay backoff.
	 */

	/* subrate_factor: reserved for BT 5.3, not parsed */

	obj = ucl_object_lookup(root, "privacy_mode");
	if (obj != NULL && ucl_object_type(obj) == UCL_STRING) {
		const char *m = ucl_object_tostring(obj);
		if (strcmp(m, "network") == 0)
			cfg->privacy_mode = 0;
		else if (strcmp(m, "device") == 0)
			cfg->privacy_mode = 1;
	}

	obj = ucl_object_lookup(root, "rpa_timeout");
	if (obj != NULL && ucl_object_type(obj) == UCL_INT)
		cfg->rpa_timeout = MAX(1,
		    MIN((int)ucl_object_toint(obj), 3600));

	obj = ucl_object_lookup(root, "peripheral_mode");
	if (obj != NULL && ucl_object_type(obj) == UCL_BOOLEAN)
		cfg->peripheral_mode = ucl_object_toboolean(obj);

	obj = ucl_object_lookup(root, "scan_mode");
	if (obj != NULL && ucl_object_type(obj) == UCL_BOOLEAN)
		cfg->scan_mode = ucl_object_toboolean(obj);
}

/*
 * Parse a GATT properties string (comma-separated tokens).
 * E.g., "read,write,notify" -> GATT_PROP_READ | GATT_PROP_WRITE | GATT_PROP_NOTIFY
 *
 * Each comma-delimited token is matched exactly to avoid substring
 * false matches (e.g., "notify_custom" would not match "notify").
 */
uint8_t
blued_parse_gatt_properties(const char *str)
{
	char buf[256];
	char *token, *saveptr;
	uint8_t props = 0;

	if (str == NULL)
		return (0);

	if (strlcpy(buf, str, sizeof(buf)) >= sizeof(buf))
		return (0);
	for (token = strtok_r(buf, ",", &saveptr); token != NULL;
	    token = strtok_r(NULL, ",", &saveptr)) {
		/* Strip leading/trailing whitespace */
		while (*token == ' ' || *token == '\t')
			token++;
		/* strtok_r() already ignores repeated delimiters; preserve that
		 * behavior for a field containing only horizontal whitespace. */
		if (*token == '\0')
			continue;
		{
			char *end = token + strlen(token) - 1;
			while (end > token && (*end == ' ' || *end == '\t'))
				*end-- = '\0';
		}

		if (strcmp(token, "broadcast") == 0)
			props |= GATT_PROP_BROADCAST;
		else if (strcmp(token, "read") == 0)
			props |= GATT_PROP_READ;
		else if (strcmp(token, "write_no_rsp") == 0)
			props |= GATT_PROP_WRITE_NO_RSP;
		else if (strcmp(token, "write") == 0)
			props |= GATT_PROP_WRITE;
		else if (strcmp(token, "notify") == 0)
			props |= GATT_PROP_NOTIFY;
		else if (strcmp(token, "indicate") == 0)
			props |= GATT_PROP_INDICATE;
		/* Removed from Core 6.3; accept old configuration for legacy peers. */
		else if (strcmp(token, "auth_signed_write") == 0)
			props |= GATT_PROP_LEGACY_AUTH_SIGNED_WRITE;
		else if (strcmp(token, "extended") == 0)
			props |= GATT_PROP_EXTENDED;
	}
	return (props);
}

/*
 * Parse a GATT permissions string (comma-separated tokens).
 * E.g., "read,write_encrypt" -> ATT_PERM_READ | ATT_PERM_WRITE_ENCRYPT
 *
 * Each comma-delimited token is matched exactly.
 */
uint8_t
blued_parse_gatt_permissions(const char *str)
{
	char buf[256];
	char *token, *saveptr;
	uint8_t perms = 0;

	if (str == NULL)
		return (0);

	if (strlcpy(buf, str, sizeof(buf)) >= sizeof(buf))
		return (0);
	for (token = strtok_r(buf, ",", &saveptr); token != NULL;
	    token = strtok_r(NULL, ",", &saveptr)) {
		while (*token == ' ' || *token == '\t')
			token++;
		if (*token == '\0')
			continue;
		{
			char *end = token + strlen(token) - 1;
			while (end > token && (*end == ' ' || *end == '\t'))
				*end-- = '\0';
		}

		if (strcmp(token, "read") == 0)
			perms |= ATT_PERM_READ;
		else if (strcmp(token, "write") == 0)
			perms |= ATT_PERM_WRITE;
		else if (strcmp(token, "read_encrypt") == 0)
			perms |= ATT_PERM_READ_ENCRYPT;
		else if (strcmp(token, "write_encrypt") == 0)
			perms |= ATT_PERM_WRITE_ENCRYPT;
		else if (strcmp(token, "read_authen") == 0)
			perms |= ATT_PERM_READ_AUTHEN;
		else if (strcmp(token, "write_authen") == 0)
			perms |= ATT_PERM_WRITE_AUTHEN;
	}
	return (perms);
}

/*
 * Parse a UUID string.
 *   "0xNNNN"                                → 16-bit UUID
 *   "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"  → 128-bit UUID (stored LE)
 *
 * Returns 0 on success, -1 on parse error.
 * On success, *uuid16 is set for 16-bit UUIDs (uuid128 untouched),
 * or *uuid16 = 0 and uuid128 is filled for 128-bit UUIDs.
 */
int
blued_parse_uuid(const char *str, uint16_t *uuid16, uint8_t uuid128[16])
{
	unsigned long val;
	unsigned int b[16];
	int i;

	if (str == NULL)
		return (-1);

	/* 16-bit UUID: "0xNNNN" */
	if (strncmp(str, "0x", 2) == 0 || strncmp(str, "0X", 2) == 0) {
		char *endp;

		val = strtoul(str, &endp, 16);
		if (*endp != '\0' || val > 0xFFFF || val == 0)
			return (-1);
		*uuid16 = (uint16_t)val;
		return (0);
	}

	/* 128-bit UUID: "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" */
	if (strlen(str) == 36 &&
	    sscanf(str,
	    "%2x%2x%2x%2x-%2x%2x-%2x%2x-%2x%2x-%2x%2x%2x%2x%2x%2x",
	    &b[0], &b[1], &b[2], &b[3],
	    &b[4], &b[5], &b[6], &b[7],
	    &b[8], &b[9], &b[10], &b[11],
	    &b[12], &b[13], &b[14], &b[15]) == 16) {
		/*
		 * Convert from big-endian display order to little-endian
		 * wire format as used by the ATT database.
		 */
		for (i = 0; i < 16; i++)
			uuid128[15 - i] = (uint8_t)b[i];
		*uuid16 = 0;
		return (0);
	}

	return (-1);
}

/*
 * Parse a hex string into a byte buffer.
 * E.g., "0100" → {0x01, 0x00}, returns 2.
 * Empty string → returns 0 (valid zero-length value).
 * Returns number of bytes parsed, or -1 on error.
 */
int
blued_parse_hex_value(const char *hex, uint8_t *out, size_t maxlen)
{
	size_t slen, i;
	unsigned int byte;

	if (hex == NULL || hex[0] == '\0')
		return (0);

	slen = strlen(hex);
	if (slen % 2 != 0)
		return (-1);
	if (slen / 2 > maxlen)
		return (-1);

	for (i = 0; i < slen; i += 2) {
		/*
		 * sscanf("%2x") accepts a single hex digit (e.g. "0g" matches
		 * just '0'), so validate BOTH nibbles are hex before parsing;
		 * otherwise a malformed token is silently accepted as a byte.
		 */
		if (!isxdigit((unsigned char)hex[i]) ||
		    !isxdigit((unsigned char)hex[i + 1]))
			return (-1);
		if (sscanf(hex + i, "%2x", &byte) != 1)
			return (-1);
		out[i / 2] = (uint8_t)byte;
	}
	return ((int)(slen / 2));
}

/*
 * Parse a single "descriptor" sub-block within a characteristic (finding 136).
 * A descriptor carries a UUID (required), optional permissions, and an optional
 * hex value.  CCCDs remain auto-generated from notify/indicate and are not
 * authored here.
 */
static void
config_parse_descriptor(struct blued_char_conf *ch, const ucl_object_t *obj,
    const char *name)
{
	const ucl_object_t *val;
	struct blued_desc_conf *d;
	const char *str;
	int len;

	if (ch->ndescs >= BLUED_MAX_CONF_DESCS ||
	    ucl_object_type(obj) != UCL_OBJECT)
		return;

	d = &ch->descs[ch->ndescs];
	memset(d, 0, sizeof(*d));

	/* UUID (required) */
	val = ucl_object_lookup(obj, "uuid");
	if (val == NULL || ucl_object_type(val) != UCL_STRING)
		return;
	if (blued_parse_uuid(ucl_object_tostring(val),
	    &d->uuid16, d->uuid128) != 0) {
		fprintf(stderr, "blued: descriptor '%s': invalid uuid '%s'\n",
		    name, ucl_object_tostring(val));
		return;
	}

	/* Permissions */
	val = ucl_object_lookup(obj, "permissions");
	if (val != NULL && ucl_object_type(val) == UCL_STRING)
		d->permissions =
		    blued_parse_gatt_permissions(ucl_object_tostring(val));

	/* Value (hex string) */
	val = ucl_object_lookup(obj, "value");
	if (val != NULL && ucl_object_type(val) == UCL_STRING) {
		str = ucl_object_tostring(val);
		len = blued_parse_hex_value(str, d->value, sizeof(d->value));
		if (len < 0) {
			fprintf(stderr, "blued: descriptor '%s': invalid hex "
			    "value '%s'\n", name, str);
			return;
		}
		d->value_len = (uint16_t)len;
	}

	ch->ndescs++;
}

/*
 * Walk the "descriptor" sub-blocks of a characteristic object, handling the
 * same three UCL shapes as the characteristic walk (single unnamed, named
 * sub-objects, unnamed array).
 */
static void
config_parse_descriptors(struct blued_char_conf *ch, const ucl_object_t *obj)
{
	const ucl_object_t *val, *d_obj;
	ucl_object_iter_t di;

	val = ucl_object_lookup(obj, "descriptor");
	if (val == NULL)
		return;
	if (ucl_object_type(val) == UCL_OBJECT) {
		if (ucl_object_lookup(val, "uuid") != NULL) {
			config_parse_descriptor(ch, val, "descriptor");
		} else {
			di = ucl_object_iterate_new(val);
			while ((d_obj = ucl_object_iterate_safe(di, true)) !=
			    NULL) {
				if (ucl_object_type(d_obj) == UCL_OBJECT)
					config_parse_descriptor(ch, d_obj,
					    ucl_object_key(d_obj));
			}
			ucl_object_iterate_free(di);
		}
	} else if (ucl_object_type(val) == UCL_ARRAY) {
		di = ucl_object_iterate_new(val);
		while ((d_obj = ucl_object_iterate_safe(di, true)) != NULL) {
			if (ucl_object_type(d_obj) == UCL_OBJECT)
				config_parse_descriptor(ch, d_obj,
				    ucl_object_key(d_obj));
		}
		ucl_object_iterate_free(di);
	}
}

/*
 * Parse a single "include" sub-block within a service (finding 136).
 * Requires start+end handles; uuid is optional.
 */
static void
config_parse_include(struct blued_service_conf *svc, const ucl_object_t *obj,
    const char *name)
{
	const ucl_object_t *val;
	struct blued_include_conf *inc;
	uint16_t uuid16 = 0;
	uint8_t uuid128[16];
	int64_t start = 0, end = 0;

	if (svc->nincludes >= BLUED_MAX_CONF_INCLUDES ||
	    ucl_object_type(obj) != UCL_OBJECT)
		return;

	val = ucl_object_lookup(obj, "start");
	if (val != NULL && ucl_object_type(val) == UCL_INT)
		start = ucl_object_toint(val);
	val = ucl_object_lookup(obj, "end");
	if (val != NULL && ucl_object_type(val) == UCL_INT)
		end = ucl_object_toint(val);
	if (start <= 0 || start > 0xffff || end <= 0 || end > 0xffff ||
	    end < start) {
		fprintf(stderr, "blued: service '%s' include '%s': invalid "
		    "start/end handle range\n", svc->name, name);
		return;
	}

	val = ucl_object_lookup(obj, "uuid");
	if (val != NULL && ucl_object_type(val) == UCL_STRING) {
		if (blued_parse_uuid(ucl_object_tostring(val), &uuid16,
		    uuid128) != 0)
			uuid16 = 0;	/* 128-bit include UUIDs are optional */
	}

	inc = &svc->includes[svc->nincludes];
	inc->start = (uint16_t)start;
	inc->end = (uint16_t)end;
	inc->uuid16 = uuid16;
	svc->nincludes++;
}

static void
config_parse_includes(struct blued_service_conf *svc, const ucl_object_t *obj)
{
	const ucl_object_t *val, *i_obj;
	ucl_object_iter_t ii;

	val = ucl_object_lookup(obj, "include");
	if (val == NULL)
		return;
	if (ucl_object_type(val) == UCL_OBJECT) {
		if (ucl_object_lookup(val, "start") != NULL) {
			config_parse_include(svc, val, "include");
		} else {
			ii = ucl_object_iterate_new(val);
			while ((i_obj = ucl_object_iterate_safe(ii, true)) !=
			    NULL) {
				if (ucl_object_type(i_obj) == UCL_OBJECT)
					config_parse_include(svc, i_obj,
					    ucl_object_key(i_obj));
			}
			ucl_object_iterate_free(ii);
		}
	} else if (ucl_object_type(val) == UCL_ARRAY) {
		ii = ucl_object_iterate_new(val);
		while ((i_obj = ucl_object_iterate_safe(ii, true)) != NULL) {
			if (ucl_object_type(i_obj) == UCL_OBJECT)
				config_parse_include(svc, i_obj,
				    ucl_object_key(i_obj));
		}
		ucl_object_iterate_free(ii);
	}
}

/*
 * Parse a single "characteristic" sub-block within a service.
 */
static void
config_parse_characteristic(struct blued_service_conf *svc,
    const ucl_object_t *obj, const char *name)
{
	const ucl_object_t *val;
	struct blued_char_conf *ch;
	const char *str;
	int len;

	if (svc->nchars >= BLUED_MAX_CONF_CHARS ||
	    ucl_object_type(obj) != UCL_OBJECT)
		return;

	ch = &svc->chars[svc->nchars];
	memset(ch, 0, sizeof(*ch));

	/* UUID (required) */
	val = ucl_object_lookup(obj, "uuid");
	if (val == NULL || ucl_object_type(val) != UCL_STRING)
		return;
	if (blued_parse_uuid(ucl_object_tostring(val),
	    &ch->uuid16, ch->uuid128) != 0) {
		fprintf(stderr, "blued: service '%s' characteristic '%s': "
		    "invalid uuid '%s'\n", svc->name, name,
		    ucl_object_tostring(val));
		return;
	}

	/* Properties */
	val = ucl_object_lookup(obj, "properties");
	if (val != NULL && ucl_object_type(val) == UCL_STRING) {
		str = ucl_object_tostring(val);
		ch->properties = blued_parse_gatt_properties(str);
	}

	/* Permissions */
	val = ucl_object_lookup(obj, "permissions");
	if (val != NULL && ucl_object_type(val) == UCL_STRING) {
		str = ucl_object_tostring(val);
		ch->permissions = blued_parse_gatt_permissions(str);
	}

	/* Initial value (hex string) */
	val = ucl_object_lookup(obj, "value");
	if (val != NULL && ucl_object_type(val) == UCL_STRING) {
		str = ucl_object_tostring(val);
		len = blued_parse_hex_value(str, ch->initial_value,
		    sizeof(ch->initial_value));
		if (len < 0) {
			fprintf(stderr, "blued: service '%s' characteristic "
			    "'%s': invalid hex value '%s'\n",
			    svc->name, name, str);
			return;
		}
		ch->initial_value_len = (uint16_t)len;
	}

	/* Auto-add CCCD if notify or indicate */
	ch->has_cccd = (ch->properties &
	    (GATT_PROP_NOTIFY | GATT_PROP_INDICATE)) != 0;

	/* Non-CCCD descriptor sub-blocks (finding 136). */
	config_parse_descriptors(ch, obj);

	svc->nchars++;
}

/*
 * Parse a single "service" block from the UCL config.
 *
 *   service "Custom Sensor" {
 *       uuid = "0xFFE0"
 *       characteristic "Sensor Data" {
 *           uuid = "0xFFE1"
 *           properties = "read,notify"
 *           permissions = "read"
 *           value = "00"
 *       }
 *   }
 */
static void
config_parse_service(struct blued_config *cfg, const ucl_object_t *obj,
    const char *name)
{
	const ucl_object_t *val;
	struct blued_service_conf *svc;

	if (cfg->nservices >= BLUED_MAX_CONF_SERVICES ||
	    ucl_object_type(obj) != UCL_OBJECT)
		return;

	svc = &cfg->services[cfg->nservices];
	memset(svc, 0, sizeof(*svc));
	if (name != NULL)
		strlcpy(svc->name, name, sizeof(svc->name));

	/* UUID (required) */
	val = ucl_object_lookup(obj, "uuid");
	if (val == NULL || ucl_object_type(val) != UCL_STRING) {
		fprintf(stderr, "blued: service '%s': missing uuid\n",
		    svc->name);
		return;
	}
	if (blued_parse_uuid(ucl_object_tostring(val),
	    &svc->uuid16, svc->uuid128) != 0) {
		fprintf(stderr, "blued: service '%s': invalid uuid '%s'\n",
		    svc->name, ucl_object_tostring(val));
		return;
	}

	/*
	 * Parse characteristic sub-blocks.
	 *
	 * UCL supports two forms:
	 *
	 * (a) Named: characteristic "Name" { uuid = "0xFFE1"; ... }
	 *     UCL creates key "characteristic" -> object with sub-key "Name"
	 *     -> object with uuid, properties, etc.
	 *
	 * (b) Unnamed: characteristic { uuid = "0xFFE1"; ... }
	 *     UCL creates key "characteristic" -> object with uuid directly.
	 *     Multiple unnamed blocks become an implicit array.
	 *
	 * Detect (a) vs (b) by checking if the object under "characteristic"
	 * contains a "uuid" key directly (form b) or sub-objects (form a).
	 */
	val = ucl_object_lookup(obj, "characteristic");
	if (val != NULL) {
		if (ucl_object_type(val) == UCL_OBJECT) {
			/* Check if this is form (b) — has uuid directly */
			if (ucl_object_lookup(val, "uuid") != NULL) {
				config_parse_characteristic(svc, val,
				    "characteristic");
			} else {
				/*
				 * Form (a) — iterate named sub-objects.
				 * Each sub-key is a characteristic name.
				 */
				ucl_object_iter_t ci;
				const ucl_object_t *ch_obj;

				ci = ucl_object_iterate_new(val);
				while ((ch_obj = ucl_object_iterate_safe(
				    ci, true)) != NULL) {
					if (ucl_object_type(ch_obj) ==
					    UCL_OBJECT)
						config_parse_characteristic(
						    svc, ch_obj,
						    ucl_object_key(ch_obj));
				}
				ucl_object_iterate_free(ci);
			}
		} else if (ucl_object_type(val) == UCL_ARRAY) {
			/* Multiple unnamed characteristic blocks */
			ucl_object_iter_t ci;
			const ucl_object_t *ch_obj;

			ci = ucl_object_iterate_new(val);
			while ((ch_obj = ucl_object_iterate_safe(
			    ci, true)) != NULL) {
				if (ucl_object_type(ch_obj) == UCL_OBJECT)
					config_parse_characteristic(svc,
					    ch_obj, ucl_object_key(ch_obj));
			}
			ucl_object_iterate_free(ci);
		}
	}

	/* Included-service sub-blocks (finding 136). */
	config_parse_includes(svc, obj);

	cfg->nservices++;
}

/*
 * Shared UCL root-object parser.
 * Extracts general, features, adapters, security, devices, and service
 * sections from the parsed UCL root and populates cfg.
 * Called from both blued_config_load (file path) and blued_config_load_fd
 * (pre-opened fd) to avoid duplicating the section-walking logic.
 */
static void
config_parse_root(struct blued_config *cfg, const ucl_object_t *root)
{
	const ucl_object_t *obj, *cur;
	ucl_object_iter_t it;

	obj = ucl_object_lookup(root, "general");
	if (obj != NULL && ucl_object_type(obj) == UCL_OBJECT)
		config_parse_general(cfg, obj);

	obj = ucl_object_lookup(root, "features");
	if (obj != NULL && ucl_object_type(obj) == UCL_OBJECT)
		config_parse_features(cfg, obj);

	/* Adapters array */
	obj = ucl_object_lookup(root, "adapters");
	if (obj != NULL && ucl_object_type(obj) == UCL_STRING) {
		if (strcmp(ucl_object_tostring(obj), "auto") == 0)
			cfg->nadapters = 0;
	} else if (obj != NULL && ucl_object_type(obj) == UCL_ARRAY) {
		cfg->nadapters = 0;
		it = ucl_object_iterate_new(obj);
		while ((cur = ucl_object_iterate_safe(it, true)) != NULL) {
			if (cfg->nadapters >= (int)nitems(cfg->adapters))
				break;
			if (ucl_object_type(cur) == UCL_STRING &&
			    strcmp(ucl_object_tostring(cur), "auto") == 0) {
				cfg->nadapters = 0;
				break;
			}
			if (ucl_object_type(cur) == UCL_STRING)
				strlcpy(cfg->adapters[cfg->nadapters++],
				    ucl_object_tostring(cur),
				    sizeof(cfg->adapters[0]));
		}
		ucl_object_iterate_free(it);
	}

	/* Security section */
	obj = ucl_object_lookup(root, "security");
	if (obj != NULL && ucl_object_type(obj) == UCL_OBJECT)
		config_parse_security(cfg, obj);

	/* Devices array */
	obj = ucl_object_lookup(root, "devices");
	if (obj != NULL && ucl_object_type(obj) == UCL_OBJECT)
		config_parse_devices(cfg, obj);

	/*
	 * Service definitions.
	 *
	 * UCL form: service "Name" { uuid = "0xFFE0"; ... }
	 * This creates key "service" -> object with sub-key "Name".
	 * Multiple service blocks with different names create sub-keys
	 * under the same "service" object.  Multiple unnamed blocks
	 * may create an implicit array.
	 */
	obj = ucl_object_lookup(root, "service");
	if (obj != NULL && ucl_object_type(obj) == UCL_OBJECT) {
		/*
		 * Distinguish a single unnamed service body from a container
		 * of named sub-services.  A body has service-level keys ("uuid"
		 * or "characteristic") directly; a named container only has
		 * sub-objects keyed by service name.  Treating a body with a
		 * "characteristic" but no "uuid" as a container would wrongly
		 * promote the characteristic block (which itself has a "uuid")
		 * into a phantom service, so route any object carrying a
		 * service-level key to config_parse_service(), where the
		 * missing-uuid check can reject it.
		 */
		if (ucl_object_lookup(obj, "uuid") != NULL ||
		    ucl_object_lookup(obj, "characteristic") != NULL) {
			config_parse_service(cfg, obj,
			    ucl_object_key(obj));
		} else {
			/* Named services: iterate sub-keys */
			ucl_object_iter_t sit;
			const ucl_object_t *sobj;

			sit = ucl_object_iterate_new(obj);
			while ((sobj = ucl_object_iterate_safe(
			    sit, true)) != NULL) {
				if (cfg->nservices >=
				    BLUED_MAX_CONF_SERVICES)
					break;
				if (ucl_object_type(sobj) == UCL_OBJECT)
					config_parse_service(cfg, sobj,
					    ucl_object_key(sobj));
			}
			ucl_object_iterate_free(sit);
		}
	} else if (obj != NULL && ucl_object_type(obj) == UCL_ARRAY) {
		ucl_object_iter_t sit;
		const ucl_object_t *sobj;

		sit = ucl_object_iterate_new(obj);
		while ((sobj = ucl_object_iterate_safe(
		    sit, true)) != NULL) {
			if (cfg->nservices >=
			    BLUED_MAX_CONF_SERVICES)
				break;
			if (ucl_object_type(sobj) == UCL_OBJECT)
				config_parse_service(cfg, sobj,
				    ucl_object_key(sobj));
		}
		ucl_object_iterate_free(sit);
	}
}

int
blued_config_load(struct blued_config *cfg, const char *path)
{
	struct ucl_parser *parser;
	ucl_object_t *root;

	if (path == NULL)
		path = BLUED_CONFIG_DEFAULT;

	parser = ucl_parser_new(0);
	if (parser == NULL)
		return (-1);

	if (!ucl_parser_add_file(parser, path)) {
		/*
		 * Config file is optional.  Return success on ENOENT
		 * so the daemon can run with defaults alone.
		 */
		if (errno == ENOENT) {
			ucl_parser_free(parser);
			return (0);
		}
		fprintf(stderr, "blued: config parse error: %s\n",
		    ucl_parser_get_error(parser));
		ucl_parser_free(parser);
		return (-1);
	}

	root = ucl_parser_get_object(parser);
	if (root == NULL) {
		ucl_parser_free(parser);
		return (-1);
	}

	config_parse_root(cfg, root);

	ucl_object_unref(root);
	ucl_parser_free(parser);
	return (0);
}

/*
 * Reload configuration from a pre-opened file descriptor.
 * Used inside Capsicum sandbox for SIGHUP reload, where opening
 * files by path is not permitted.  Seeks to beginning before reading.
 */
int
blued_config_load_fd(struct blued_config *cfg, int fd)
{
	struct ucl_parser *parser;
	ucl_object_t *root;
	char *buf;
	struct stat st;
	size_t off;
	ssize_t n;

	if (fd < 0)
		return (-1);

	if (fstat(fd, &st) < 0 || st.st_size <= 0 || st.st_size > 1024 * 1024)
		return (-1);

	if (lseek(fd, 0, SEEK_SET) < 0)
		return (-1);

	buf = malloc((size_t)st.st_size + 1);
	if (buf == NULL)
		return (-1);

	/*
	 * A regular-file read may be short (and may be interrupted).  Parsing a
	 * prefix as a complete reload can silently apply a valid but unintended
	 * configuration, so require the exact size observed by fstat().  A file
	 * concurrently truncated or replaced is rejected and can be retried on a
	 * later reload.
	 */
	off = 0;
	while (off < (size_t)st.st_size) {
		n = read(fd, buf + off, (size_t)st.st_size - off);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			free(buf);
			return (-1);
		}
		off += (size_t)n;
	}
	buf[off] = '\0';

	parser = ucl_parser_new(0);
	if (parser == NULL) {
		free(buf);
		return (-1);
	}

	if (!ucl_parser_add_string(parser, buf, off)) {
		free(buf);
		ucl_parser_free(parser);
		return (-1);
	}
	free(buf);

	root = ucl_parser_get_object(parser);
	if (root == NULL) {
		ucl_parser_free(parser);
		return (-1);
	}

	config_parse_root(cfg, root);

	ucl_object_unref(root);
	ucl_parser_free(parser);
	return (0);
}

void
blued_config_apply_cli(struct blued_config *cfg, int argc, char **argv)
{
	int ch;

	optreset = 1;
	optind = 1;

	while ((ch = getopt(argc, argv, "a:Bc:df:hL:prsv")) != -1) {
		switch (ch) {
		case 'a':
			if (cfg->nadapters < (int)nitems(cfg->adapters))
				strlcpy(cfg->adapters[cfg->nadapters++],
				    optarg, sizeof(cfg->adapters[0]));
			break;
		case 'B':
			cfg->daemonize = true;
			break;
		case 'c':
			/* Config file already loaded before this call */
			break;
		case 'd':
			if (cfg->loglevel < 1)
				cfg->loglevel = 1;
			break;
		case 'f':
			strlcpy(cfg->bonddb, optarg, sizeof(cfg->bonddb));
			break;
		case 'h':
			break;
		case 'L':
			strlcpy(cfg->logfile, optarg, sizeof(cfg->logfile));
			break;
		case 'p':
			cfg->peripheral_mode = true;
			break;
		case 'r':
			cfg->reconnect = true;
			break;
		case 's':
			cfg->scan_mode = true;
			break;
		case 'v':
			if (cfg->loglevel < 5)
				cfg->loglevel++;
			break;
		default:
			break;
		}
	}
}
