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

#include "config.h"
#include "smp.h"
#include "ble_util.h"
#include "hci_log.h"

void
blued_config_defaults(struct blued_config *cfg)
{

	memset(cfg, 0, sizeof(*cfg));
	strlcpy(cfg->pidfile, "/var/run/blued.pid", sizeof(cfg->pidfile));
	strlcpy(cfg->bonddb, "/var/db/blued/bonds", sizeof(cfg->bonddb));
	strlcpy(cfg->ctlsock, "/var/run/blued.sock", sizeof(cfg->ctlsock));
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
	cfg->reconnect_max_delay = 60;

	cfg->peripheral_mode = false;
	cfg->scan_mode = false;
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
	if (strcmp(str, "no_input_no_output") == 0)
		return (SMP_IO_NO_INPUT_NO_OUTPUT);
	if (strcmp(str, "keyboard_display") == 0)
		return (SMP_IO_KEYBOARD_DISPLAY);
	return (SMP_IO_KEYBOARD_DISPLAY);	/* default */
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
}

int
blued_config_load(struct blued_config *cfg, const char *path)
{
	struct ucl_parser *parser;
	ucl_object_t *root;
	const ucl_object_t *obj, *cur;
	ucl_object_iter_t it;

	if (path == NULL)
		path = "/etc/blued.conf";

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
			cfg->loglevel++;
			break;
		default:
			break;
		}
	}
}
