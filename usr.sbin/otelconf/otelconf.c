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

	return (sc->endpoint[0] != '\0');
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
		warnx("no export target: set endpoint in otel.conf");
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
	else
		return (-1);
	return (0);
}

static const char *const show_keys[] = {
	"enable", "endpoint", "protocol", "compression", "timeout_ms",
	"headers_file", "host_id_file", "spool.directory", "spool.max_bytes",
	NULL
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
