/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * UCL configuration file parser for oracled.
 *
 * Reads /etc/oracled.conf (or a path given with -f) and populates
 * struct oracled_config.  Missing file is not an error — defaults
 * apply.  Syntax errors are fatal.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <ucl.h>

#include "config.h"

void
config_init_defaults(struct oracled_config *cfg)
{

	memset(cfg, 0, sizeof(*cfg));
	strlcpy(cfg->pidfile, ORACLED_DEFAULT_PIDFILE,
	    sizeof(cfg->pidfile));
	strlcpy(cfg->control_socket, ORACLED_DEFAULT_CTLSOCK,
	    sizeof(cfg->control_socket));
	cfg->control_socket_mode = ORACLED_DEFAULT_CTLMODE;

	/* Shield defaults: conservative — don't break rc(8). */
	cfg->shield_ptrace = true;
	cfg->shield_signal = false;
	cfg->shield_visible = false;
	cfg->shield_wait = true;
	cfg->shield_sched = true;
	cfg->shield_core = false;
	cfg->shield_ktrace = true;

	cfg->isolate_cap_rt = true;
}

/*
 * Read a boolean from a UCL object, leaving *val unchanged if
 * the key is absent.
 */
static void
cfg_bool(const ucl_object_t *obj, const char *key, bool *val)
{
	const ucl_object_t *o;

	o = ucl_object_lookup(obj, key);
	if (o != NULL && ucl_object_type(o) == UCL_BOOLEAN)
		*val = ucl_object_toboolean(o);
}

/*
 * Read a string from a UCL object into a fixed buffer, leaving
 * the buffer unchanged if the key is absent.
 */
static void
cfg_string(const ucl_object_t *obj, const char *key,
    char *buf, size_t bufsz)
{
	const ucl_object_t *o;

	o = ucl_object_lookup(obj, key);
	if (o != NULL && ucl_object_type(o) == UCL_STRING)
		strlcpy(buf, ucl_object_tostring(o), bufsz);
}

int
config_load(struct oracled_config *cfg, const char *path)
{
	struct ucl_parser *parser;
	const ucl_object_t *root, *shield, *isolation;

	if (access(path, R_OK) != 0) {
		if (errno == ENOENT)
			return (0);	/* missing file — use defaults */
		fprintf(stderr, "oracled: %s: %s\n", path, strerror(errno));
		return (-1);
	}

	parser = ucl_parser_new(UCL_PARSER_DEFAULT);
	if (parser == NULL) {
		fprintf(stderr, "oracled: ucl_parser_new failed\n");
		return (-1);
	}

	if (!ucl_parser_add_file(parser, path)) {
		fprintf(stderr, "oracled: %s: %s\n", path,
		    ucl_parser_get_error(parser));
		ucl_parser_free(parser);
		return (-1);
	}

	root = ucl_parser_get_object(parser);
	if (root == NULL) {
		fprintf(stderr, "oracled: %s: empty config\n", path);
		ucl_parser_free(parser);
		return (-1);
	}

	/* Top-level keys */
	cfg_string(root, "pidfile", cfg->pidfile, sizeof(cfg->pidfile));
	cfg_string(root, "control_socket", cfg->control_socket,
	    sizeof(cfg->control_socket));

	/* Parse mode as a string to support octal (e.g., "0700"). */
	{
		const ucl_object_t *o;
		o = ucl_object_lookup(root, "control_socket_mode");
		if (o != NULL) {
			if (ucl_object_type(o) == UCL_STRING) {
				cfg->control_socket_mode = (mode_t)
				    strtol(ucl_object_tostring(o), NULL, 0);
			} else if (ucl_object_type(o) == UCL_INT) {
				cfg->control_socket_mode = (mode_t)
				    ucl_object_toint(o);
			}
		}
	}

	/* Shield section */
	shield = ucl_object_lookup(root, "shield");
	if (shield != NULL && ucl_object_type(shield) == UCL_OBJECT) {
		cfg_bool(shield, "ptrace", &cfg->shield_ptrace);
		cfg_bool(shield, "signal", &cfg->shield_signal);
		cfg_bool(shield, "visible", &cfg->shield_visible);
		cfg_bool(shield, "wait", &cfg->shield_wait);
		cfg_bool(shield, "sched", &cfg->shield_sched);
		cfg_bool(shield, "core", &cfg->shield_core);
		cfg_bool(shield, "ktrace", &cfg->shield_ktrace);
	}

	/* Isolation section */
	isolation = ucl_object_lookup(root, "isolation");
	if (isolation != NULL &&
	    ucl_object_type(isolation) == UCL_OBJECT) {
		cfg_bool(isolation, "cap_rt", &cfg->isolate_cap_rt);
	}

	ucl_object_unref(__DECONST(ucl_object_t *, root));
	ucl_parser_free(parser);

	cfg->loaded_from_file = true;
	return (0);
}

void
config_log(const struct oracled_config *cfg)
{

	if (cfg->loaded_from_file)
		syslog(LOG_INFO, "config: loaded from file");
	else
		syslog(LOG_INFO, "config: using defaults");
	syslog(LOG_INFO, "config: pidfile=%s", cfg->pidfile);
	syslog(LOG_INFO, "config: control_socket=%s mode=%04o",
	    cfg->control_socket, cfg->control_socket_mode);
	syslog(LOG_INFO, "config: shield ptrace=%d signal=%d visible=%d "
	    "wait=%d sched=%d core=%d ktrace=%d",
	    cfg->shield_ptrace, cfg->shield_signal, cfg->shield_visible,
	    cfg->shield_wait, cfg->shield_sched, cfg->shield_core,
	    cfg->shield_ktrace);
	syslog(LOG_INFO, "config: isolate_cap_rt=%d", cfg->isolate_cap_rt);
}
