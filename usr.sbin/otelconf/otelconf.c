/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * otelconf - validate and query the system OpenTelemetry configuration
 * (otel.conf(5)).
 */

#include <sys/param.h>

#include <err.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "otelexport.h"
#include "oe_sysconf.h"

static const char *defaults_path;	/* NULL: standard */
static const char *config_path;		/* NULL: standard */

static void __dead2
usage(void)
{

	fprintf(stderr,
	    "usage: otelconf [-d defaults] [-f file] check [-eqt]\n"
	    "       otelconf [-d defaults] [-f file] show\n"
	    "       otelconf [-d defaults] [-f file] get key\n");
	exit(2);
}

static void
load(struct oe_sysconf *sc)
{

	if (oe_sysconf_load(sc, defaults_path, config_path) != 0)
		errx(1, "%s", sc->error);
}

/* Does the configuration name somewhere to export to? */
static int
has_target(const struct oe_sysconf *sc)
{

	int i;

	if (sc->export_file || sc->endpoint[0] != '\0')
		return (1);
	/* A signal block's endpoint is a target for that signal. */
	for (i = 0; i < OE_NSIGNALS; i++)
		if (sc->signals[i].endpoint != NULL &&
		    sc->signals[i].endpoint[0] != '\0')
			return (1);
	return (0);
}

static int
cmd_check(int argc, char **argv)
{
	struct oe_sysconf sc;
	int ch, need_enable, need_target, quiet;

	need_enable = need_target = quiet = 0;
	while ((ch = getopt(argc, argv, "eqt")) != -1) {
		switch (ch) {
		case 'e':
			need_enable = 1;
			break;
		case 'q':
			quiet = 1;
			break;
		case 't':
			need_target = 1;
			break;
		default:
			usage();
		}
	}
	if (optind != argc)
		usage();
	load(&sc);
	if (need_enable && !sc.enable) {
		warnx("the system configuration is disabled "
		    "(enable = false)");
		oe_sysconf_free(&sc);
		return (3);
	}
	if (need_target && !has_target(&sc)) {
		warnx("no export target: set endpoint, or export.target = "
		    "\"file\", in otel.conf");
		oe_sysconf_free(&sc);
		return (4);
	}
	if (!quiet)
		printf("otel.conf: OK%s%s\n", sc.enable ? "" : " (disabled)",
		    has_target(&sc) ? "" : " (no export target)");
	oe_sysconf_free(&sc);
	return (0);
}

static void
print_list(const struct oe_attr *a, size_t n, int redact)
{
	size_t i;

	for (i = 0; i < n; i++)
		printf("%s=%s\n", a[i].name, redact ? "<redacted>" :
		    a[i].value);
}

/*
 * <signal>.endpoint, .protocol, .compression, .timeout_ms, .headers_file
 * of a signal block; unset ones print empty (the general key applies).
 */
static int
print_signal_key(const struct oe_sysconf *sc, const char *key)
{
	const struct oe_sysconf_signal *ss;
	const char *dot, *v;
	size_t len;
	int i;

	if ((dot = strchr(key, '.')) == NULL)
		return (-1);
	len = (size_t)(dot - key);
	for (i = 0; i < OE_NSIGNALS; i++)
		if (strlen(oe_signal_name((enum oe_signal)i)) == len &&
		    strncmp(key, oe_signal_name((enum oe_signal)i), len) == 0)
			break;
	if (i == OE_NSIGNALS)
		return (-1);
	ss = &sc->signals[i];
	if (strcmp(dot + 1, "timeout_ms") == 0) {
		if (ss->timeout_ms > 0)
			printf("%d\n", ss->timeout_ms);
		else
			printf("\n");
		return (0);
	}
	if (strcmp(dot + 1, "endpoint") == 0)
		v = ss->endpoint;
	else if (strcmp(dot + 1, "protocol") == 0)
		v = ss->protocol;
	else if (strcmp(dot + 1, "compression") == 0)
		v = ss->compression;
	else if (strcmp(dot + 1, "headers_file") == 0)
		v = ss->headers_file;
	else
		return (-1);
	printf("%s\n", v != NULL ? v : "");
	return (0);
}

static int
print_key(const struct oe_sysconf *sc, const char *key)
{

	if (strcmp(key, "enable") == 0)
		printf("%s\n", sc->enable ? "true" : "false");
	else if (strcmp(key, "endpoint") == 0)
		printf("%s\n", sc->endpoint);
	else if (strcmp(key, "protocol") == 0)
		printf("%s\n", sc->protocol);
	else if (strcmp(key, "compression") == 0)
		printf("%s\n", sc->compression);
	else if (strcmp(key, "timeout_ms") == 0)
		printf("%d\n", sc->timeout_ms);
	else if (strcmp(key, "headers_file") == 0)
		printf("%s\n", sc->headers_file);
	else if (strcmp(key, "host_id_file") == 0)
		printf("%s\n", sc->host_id_file);
	else if (strcmp(key, "resource") == 0)
		print_list(sc->resource_attrs, sc->nresource_attrs, 0);
	else if (strcmp(key, "spool.directory") == 0)
		printf("%s\n", sc->spool_dir);
	else if (strcmp(key, "spool.max_bytes") == 0)
		printf("%" PRIu64 "\n", sc->spool_max_bytes);
	else if (strcmp(key, "export.target") == 0)
		printf("%s\n", sc->export_file ? "file" : "otlp");
	else if (strcmp(key, "export.directory") == 0)
		printf("%s\n", sc->export_dir);
	else
		return (print_signal_key(sc, key));
	return (0);
}

static const char *const show_keys[] = {
	"enable", "endpoint", "protocol", "compression", "timeout_ms",
	"headers_file", "host_id_file", "spool.directory", "spool.max_bytes",
	"export.target", "export.directory", NULL
};

static int
cmd_show(int argc, char **argv __unused)
{
	struct oe_sysconf sc;
	size_t i;

	if (argc != 1)
		usage();
	load(&sc);
	for (i = 0; show_keys[i] != NULL; i++) {
		printf("%s = ", show_keys[i]);
		(void)print_key(&sc, show_keys[i]);
	}
	/* The signal blocks' settings, the ones that are set. */
	for (i = 0; i < OE_NSIGNALS; i++) {
		static const char *const skeys[] = { "endpoint", "protocol",
		    "compression", "timeout_ms", "headers_file" };
		const struct oe_sysconf_signal *ss = &sc.signals[i];
		const char *set[] = { ss->endpoint, ss->protocol,
		    ss->compression, ss->timeout_ms > 0 ? "" : NULL,
		    ss->headers_file };
		char key[64];
		size_t k;

		for (k = 0; k < nitems(skeys); k++) {
			if (set[k] == NULL)
				continue;
			snprintf(key, sizeof(key), "%s.%s",
			    oe_signal_name((enum oe_signal)i), skeys[k]);
			printf("%s = ", key);
			(void)print_key(&sc, key);
		}
	}
	printf("# headers (%zu, values redacted)\n", sc.nheaders);
	print_list(sc.headers, sc.nheaders, 1);
	printf("# resource (%zu)\n", sc.nresource_attrs);
	print_list(sc.resource_attrs, sc.nresource_attrs, 0);
	oe_sysconf_free(&sc);
	return (0);
}

static int
cmd_get(int argc, char **argv)
{
	struct oe_sysconf sc;

	if (argc != 2)
		usage();
	load(&sc);
	if (print_key(&sc, argv[1]) != 0) {
		oe_sysconf_free(&sc);
		errx(2, "unknown key: %s", argv[1]);
	}
	oe_sysconf_free(&sc);
	return (0);
}

int
main(int argc, char **argv)
{
	int ch;

	while ((ch = getopt(argc, argv, "+d:f:")) != -1) {
		switch (ch) {
		case 'd':
			defaults_path = optarg;
			break;
		case 'f':
			config_path = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc < 1)
		usage();
	optind = 1;
	optreset = 1;
	if (strcmp(argv[0], "check") == 0)
		return (cmd_check(argc, argv));
	if (strcmp(argv[0], "show") == 0)
		return (cmd_show(argc, argv));
	if (strcmp(argv[0], "get") == 0)
		return (cmd_get(argc, argv));
	usage();
}
