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
 *       sc_only = false;
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

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>
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
	cfg->sc_only = false;

	cfg->eatt = true;
	cfg->privacy = true;
	cfg->reconnect = true;
	cfg->reconnect_max_delay = BLUED_RECONNECT_MAX_DEFAULT;

	cfg->min_key_size = BLUED_MIN_KEY_SIZE_DEFAULT;
	cfg->rpa_timeout = BLUED_RPA_TIMEOUT_DEFAULT;
	cfg->privacy_mode = 1;			/* device privacy (default) */
	cfg->subrate_factor = 0;		/* disabled by default */
	cfg->socket_pool_size = BLUED_SOCKET_POOL_DEFAULT;

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

	val = ucl_object_lookup(obj, "sc_only");
	if (val != NULL && ucl_object_type(val) == UCL_BOOLEAN)
		cfg->sc_only = ucl_object_toboolean(val);

	val = ucl_object_lookup(obj, "min_key_size");
	if (val != NULL && ucl_object_type(val) == UCL_INT)
		cfg->min_key_size = MAX(7,
		    MIN((int)ucl_object_toint(val), 16));
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

	obj = ucl_object_lookup(root, "subrate_factor");
	if (obj != NULL && ucl_object_type(obj) == UCL_INT)
		cfg->subrate_factor = MAX(0,
		    MIN((int)ucl_object_toint(obj), 500));

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

	obj = ucl_object_lookup(root, "socket_pool_size");
	if (obj != NULL && ucl_object_type(obj) == UCL_INT)
		cfg->socket_pool_size = MAX(1,
		    MIN((int)ucl_object_toint(obj), 64));

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

	strlcpy(buf, str, sizeof(buf));
	for (token = strtok_r(buf, ",", &saveptr); token != NULL;
	    token = strtok_r(NULL, ",", &saveptr)) {
		/* Strip leading/trailing whitespace */
		while (*token == ' ' || *token == '\t')
			token++;
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
		else if (strcmp(token, "auth_signed_write") == 0)
			props |= GATT_PROP_AUTH_SIGNED_WRITE;
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

	strlcpy(buf, str, sizeof(buf));
	for (token = strtok_r(buf, ",", &saveptr); token != NULL;
	    token = strtok_r(NULL, ",", &saveptr)) {
		while (*token == ' ' || *token == '\t')
			token++;
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
		if (sscanf(hex + i, "%2x", &byte) != 1)
			return (-1);
		out[i / 2] = (uint8_t)byte;
	}
	return ((int)(slen / 2));
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

	cfg->nservices++;
}

int
blued_config_load(struct blued_config *cfg, const char *path)
{
	struct ucl_parser *parser;
	ucl_object_t *root;
	const ucl_object_t *obj, *cur;
	ucl_object_iter_t it;

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
		/* Check if this is a single unnamed service
		 * (has "uuid" directly) or named sub-services */
		if (ucl_object_lookup(obj, "uuid") != NULL) {
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
