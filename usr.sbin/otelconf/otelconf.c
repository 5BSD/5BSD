/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * otelconf - validate and query the system OpenTelemetry configuration
 * (otel.conf(5)) and render the local agent configuration from it.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "otelexport.h"
#include "oe_http.h"
#include "oe_sysconf.h"

static const char *defaults_path;	/* NULL: standard */
static const char *config_path;		/* NULL: standard */

static void __dead2
usage(void)
{

	fprintf(stderr,
	    "usage: otelconf [-d defaults] [-f file] check [-eq]\n"
	    "       otelconf [-d defaults] [-f file] show\n"
	    "       otelconf [-d defaults] [-f file] get key\n"
	    "       otelconf [-d defaults] [-f file] fluentbit [-o file] "
	    "[-u user]\n");
	exit(2);
}

static void
load(struct oe_sysconf *sc)
{

	if (oe_sysconf_load(sc, defaults_path, config_path) != 0)
		errx(1, "%s", sc->error);
}

/* Check the agent credentials file too; it is read only by the agent. */
static void
load_agent_headers(const struct oe_sysconf *sc, struct oe_attr **h,
    size_t *n)
{
	char err[512];

	*h = NULL;
	*n = 0;
	if (sc->agent_headers_file[0] == '\0')
		return;
	if (oe_headers_file_load(sc->agent_headers_file, h, n, err,
	    sizeof(err)) != 0)
		errx(1, "agent.headers_file: %s", err);
}

static int
cmd_check(int argc, char **argv)
{
	struct oe_sysconf sc;
	struct oe_attr *h;
	size_t n;
	int ch, need_enable, quiet;

	need_enable = quiet = 0;
	while ((ch = getopt(argc, argv, "eq")) != -1) {
		switch (ch) {
		case 'e':
			need_enable = 1;
			break;
		case 'q':
			quiet = 1;
			break;
		default:
			usage();
		}
	}
	if (optind != argc)
		usage();
	load(&sc);
	load_agent_headers(&sc, &h, &n);
	oe_attrs_free(h, n);
	if (need_enable && !sc.enable) {
		warnx("the system configuration is disabled "
		    "(enable = false)");
		oe_sysconf_free(&sc);
		return (3);
	}
	if (!quiet)
		printf("otel.conf: OK%s\n", sc.enable ? "" : " (disabled)");
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
 * Split agent.listen into host and port.  The value was validated by
 * the loader as "ipv4:port" or "[ipv6]:port".
 */
static void
split_listen(const char *listen, char *host, size_t hostlen,
    const char **port)
{
	const char *colon;

	colon = strrchr(listen, ':');
	*port = colon + 1;
	if (listen[0] == '[')
		snprintf(host, hostlen, "%.*s", (int)(colon - listen - 2),
		    listen + 1);
	else
		snprintf(host, hostlen, "%.*s", (int)(colon - listen),
		    listen);
}

static int
print_key(const struct oe_sysconf *sc, const char *key)
{
	char host[64];
	const char *port;
	size_t i;

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
	else if (strcmp(key, "agent.listen") == 0)
		printf("%s\n", sc->agent_listen);
	else if (strcmp(key, "agent.listen.host") == 0) {
		split_listen(sc->agent_listen, host, sizeof(host), &port);
		printf("%s\n", host);
	} else if (strcmp(key, "agent.listen.port") == 0) {
		split_listen(sc->agent_listen, host, sizeof(host), &port);
		printf("%s\n", port);
	} else if (strcmp(key, "agent.upstream") == 0)
		printf("%s\n", sc->agent_upstream);
	else if (strcmp(key, "agent.upstream_protocol") == 0)
		printf("%s\n", sc->agent_upstream_protocol);
	else if (strcmp(key, "agent.headers_file") == 0)
		printf("%s\n", sc->agent_headers_file);
	else if (strcmp(key, "agent.tls_verify") == 0)
		printf("%s\n", sc->agent_tls_verify ? "true" : "false");
	else if (strcmp(key, "agent.log_level") == 0)
		printf("%s\n", sc->agent_log_level);
	else if (strcmp(key, "agent.tail") == 0) {
		for (i = 0; i < sc->nagent_tail; i++)
			printf("%s\n", sc->agent_tail[i]);
	} else
		return (-1);
	return (0);
}

static const char *const show_keys[] = {
	"enable", "endpoint", "protocol", "compression", "timeout_ms",
	"headers_file", "host_id_file", "spool.directory", "spool.max_bytes",
	"agent.listen", "agent.upstream", "agent.upstream_protocol",
	"agent.headers_file", "agent.tls_verify", "agent.log_level", NULL
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
	printf("# agent.tail (%zu)\n", sc.nagent_tail);
	(void)print_key(&sc, "agent.tail");
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

/* ---------------------------------------------------------------- */
/* Fluent Bit configuration						*/

/* Write s as a YAML single-quoted scalar. */
static void
yq(FILE *f, const char *s)
{

	fputc('\'', f);
	for (; *s != '\0'; s++) {
		if (*s == '\'')
			fputc('\'', f);
		fputc(*s, f);
	}
	fputc('\'', f);
}

static void
render_fluentbit(FILE *f, const struct oe_sysconf *sc,
    const struct oe_url *up, const struct oe_attr *h, size_t nh)
{
	char host[64], path[PATH_MAX];
	const char *port;
	size_t i;

	split_listen(sc->agent_listen, host, sizeof(host), &port);
	fprintf(f,
	    "# Generated by otelconf(8) from otel.conf(5); do not edit.\n"
	    "# Regenerated by the fluentbit rc.d script on every start.\n"
	    "service:\n"
	    "  flush: 1\n"
	    "  grace: 5\n"
	    "  daemon: off\n"
	    "  log_level: %s\n"
	    "  http_server: off\n"
	    "  storage.path: ", sc->agent_log_level);
	snprintf(path, sizeof(path), "%s/fluent-bit", sc->spool_dir);
	yq(f, path);
	fprintf(f, "\n"
	    "  storage.sync: normal\n"
	    "  storage.checksum: on\n"
	    "  storage.backlog.mem_limit: 16M\n"
	    "  storage.max_chunks_up: 64\n"
	    "  storage.delete_irrecoverable_chunks: on\n"
	    "\n"
	    "pipeline:\n"
	    "  inputs:\n"
	    "    # OTLP/HTTP receiver for the base system emitters.\n"
	    "    - name: opentelemetry\n"
	    "      listen: ");
	yq(f, host);
	fprintf(f, "\n"
	    "      port: %s\n"
	    "      storage.type: filesystem\n", port);
	if (sc->nagent_tail > 0) {
		fprintf(f, "    # Text logs (otel.conf agent.tail).\n"
		    "    - name: tail\n"
		    "      tag: host.logs\n"
		    "      path: '");
		for (i = 0; i < sc->nagent_tail; i++)
			fprintf(f, "%s%s", i > 0 ? "," : "",
			    sc->agent_tail[i]);
		fprintf(f, "'\n      db: ");
		snprintf(path, sizeof(path), "%s/fluent-bit/tail.db",
		    sc->spool_dir);
		yq(f, path);
		fprintf(f, "\n"
		    "      read_from_head: false\n"
		    "      skip_long_lines: on\n"
		    "      storage.type: filesystem\n");
	}
	fprintf(f, "\n"
	    "  outputs:\n"
	    "    - name: opentelemetry\n"
	    "      match: '*'\n"
	    "      host: ");
	yq(f, up->host);
	fprintf(f, "\n"
	    "      port: %d\n"
	    "      metrics_uri: ", up->port);
	snprintf(path, sizeof(path), "%s/v1/metrics", up->basepath);
	yq(f, path);
	fprintf(f, "\n      logs_uri: ");
	snprintf(path, sizeof(path), "%s/v1/logs", up->basepath);
	yq(f, path);
	fprintf(f, "\n      traces_uri: ");
	snprintf(path, sizeof(path), "%s/v1/traces", up->basepath);
	yq(f, path);
	fprintf(f, "\n"
	    "      tls: %s\n"
	    "      tls.verify: %s\n",
	    up->tls ? "on" : "off", sc->agent_tls_verify ? "on" : "off");
	/* Emit optional properties only when they differ from the default. */
	if (strcmp(sc->agent_upstream_protocol, "grpc") == 0)
		fprintf(f, "      grpc: on\n");
	if (strcmp(sc->compression, "gzip") == 0)
		fprintf(f, "      compress: gzip\n");
	fprintf(f,
	    "      retry_limit: no_limits\n"
	    "      storage.total_limit_size: %" PRIu64 "M\n",
	    sc->spool_max_bytes / (1024 * 1024));
	if (nh > 0) {
		fprintf(f, "      header:\n");
		for (i = 0; i < nh; i++) {
			char line[OE_SYSCONF_KEY_MAX + OE_SYSCONF_VALUE_MAX +
			    2];

			snprintf(line, sizeof(line), "%s %s", h[i].name,
			    h[i].value);
			fprintf(f, "        - ");
			yq(f, line);
			fputc('\n', f);
		}
	}
}

static int
cmd_fluentbit(int argc, char **argv)
{
	struct oe_sysconf sc;
	struct oe_url up;
	struct oe_attr *h;
	struct passwd *pw;
	const char *output, *user;
	char tmp[PATH_MAX], dirbuf[PATH_MAX];
	size_t nh;
	FILE *f;
	int ch, fd;

	output = user = NULL;
	while ((ch = getopt(argc, argv, "o:u:")) != -1) {
		switch (ch) {
		case 'o':
			output = optarg;
			break;
		case 'u':
			user = optarg;
			break;
		default:
			usage();
		}
	}
	if (optind != argc || (user != NULL && output == NULL))
		usage();
	pw = NULL;
	if (user != NULL && (pw = getpwnam(user)) == NULL)
		errx(1, "unknown user %s", user);
	load(&sc);
	if (!sc.enable)
		errx(3, "the system configuration is disabled "
		    "(enable = false)");
	if (sc.agent_upstream[0] == '\0')
		errx(1, "agent.upstream is not set in otel.conf; the local "
		    "agent has nowhere to forward telemetry");
	/* The loader validated the URL. */
	(void)oe_url_parse(sc.agent_upstream, &up);
	load_agent_headers(&sc, &h, &nh);

	if (output == NULL) {
		render_fluentbit(stdout, &sc, &up, h, nh);
		oe_attrs_free(h, nh);
		oe_sysconf_free(&sc);
		return (fflush(stdout) == 0 ? 0 : 1);
	}
	/*
	 * Write the configuration (it may hold credentials) to a 0600
	 * temporary file in the destination directory, then rename it.
	 */
	if (strlcpy(dirbuf, output, sizeof(dirbuf)) >= sizeof(dirbuf) ||
	    snprintf(tmp, sizeof(tmp), "%s/.otelconf.XXXXXX",
	    dirname(dirbuf)) >= (int)sizeof(tmp))
		errx(1, "%s: path too long", output);
	fd = mkstemp(tmp);
	if (fd == -1)
		err(1, "%s", tmp);
	if (pw != NULL && fchown(fd, pw->pw_uid, pw->pw_gid) != 0) {
		warn("fchown %s", tmp);
		goto fail;
	}
	f = fdopen(fd, "w");
	if (f == NULL) {
		warn("fdopen");
		goto fail;
	}
	render_fluentbit(f, &sc, &up, h, nh);
	if (fflush(f) != 0 || fsync(fileno(f)) != 0) {
		warn("%s", tmp);
		fclose(f);
		fd = -1;
		goto fail;
	}
	fclose(f);
	if (rename(tmp, output) != 0) {
		warn("rename %s", output);
		fd = -1;
		goto fail;
	}
	oe_attrs_free(h, nh);
	oe_sysconf_free(&sc);
	return (0);
fail:
	if (fd != -1)
		close(fd);
	unlink(tmp);
	oe_attrs_free(h, nh);
	oe_sysconf_free(&sc);
	return (1);
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
	if (strcmp(argv[0], "fluentbit") == 0)
		return (cmd_fluentbit(argc, argv));
	usage();
}
