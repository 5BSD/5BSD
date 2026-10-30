/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Tests for the otel.conf(5) system configuration layer.
 */

#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <atf-c.h>

#include "otelexport.h"
#include "oe_sysconf.h"

static void
write_file(const char *path, const char *text, mode_t mode)
{
	FILE *f;

	(void)unlink(path);
	f = fopen(path, "w");
	ATF_REQUIRE_MSG(f != NULL, "fopen %s: %s", path, strerror(errno));
	ATF_REQUIRE(fputs(text, f) >= 0);
	ATF_REQUIRE(fclose(f) == 0);
	ATF_REQUIRE(chmod(path, mode) == 0);
}

static const char *
attr(const struct oe_attr *a, size_t n, const char *name)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (strcmp(a[i].name, name) == 0)
			return (a[i].value);
	return (NULL);
}

/* Load "text" as the local file (no defaults) and expect failure. */
static void
expect_error(const char *text, const char *needle)
{
	struct oe_sysconf sc;

	write_file("bad.conf", text, 0644);
	ATF_REQUIRE_EQ_MSG(oe_sysconf_load(&sc, "", "bad.conf"), -1,
	    "accepted: %s", text);
	ATF_CHECK_MSG(strstr(sc.error, needle) != NULL,
	    "error \"%s\" lacks \"%s\"", sc.error, needle);
	/* A failed load leaves built-in defaults behind. */
	ATF_CHECK_STREQ(sc.endpoint, OE_SYSCONF_DEFAULT_ENDPOINT);
	oe_sysconf_free(&sc);
}

static void
clear_env(void)
{

	unsetenv("OTEL_SERVICE_NAME");
	unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT");
	unsetenv("OTEL_EXPORTER_OTLP_COMPRESSION");
	unsetenv("OTEL_EXPORTER_OTLP_TIMEOUT");
	unsetenv("OTEL_RESOURCE_ATTRIBUTES");
	unsetenv("OTEL_EXPORTER_OTLP_HEADERS");
}

ATF_TC_WITHOUT_HEAD(builtin_defaults);
ATF_TC_BODY(builtin_defaults, tc)
{
	struct oe_sysconf sc;

	ATF_REQUIRE_EQ(oe_sysconf_load(&sc, "", ""), 0);
	ATF_CHECK_EQ(sc.enable, 1);
	/* No receiver is configured out of the box (no local agent). */
	ATF_CHECK_STREQ(sc.endpoint, "");
	ATF_CHECK_STREQ(sc.protocol, "http/json");
	ATF_CHECK_STREQ(sc.compression, "gzip");
	ATF_CHECK_EQ(sc.timeout_ms, 10000);
	ATF_CHECK_STREQ(sc.headers_file, "");
	ATF_CHECK_EQ(sc.nheaders, 0);
	ATF_CHECK_STREQ(sc.spool_dir, "/var/spool/otel");
	ATF_CHECK_EQ(sc.spool_max_bytes, 256ULL * 1024 * 1024);
	ATF_CHECK_EQ(sc.export_file, 0);
	ATF_CHECK_STREQ(sc.export_dir, "/var/log/otel");
	oe_sysconf_free(&sc);
	/* Freeing twice is harmless. */
	oe_sysconf_free(&sc);
}

ATF_TC_WITHOUT_HEAD(standard_paths);
ATF_TC_BODY(standard_paths, tc)
{
	struct oe_sysconf sc;

	/*
	 * NULL selects /etc/defaults/otel.conf and /etc/otel.conf.  Their
	 * presence depends on the host, but the shipped files are valid.
	 */
	unsetenv("OTELCONF_DEFAULTS");
	unsetenv("OTELCONF_FILE");
	ATF_CHECK_EQ_MSG(oe_sysconf_load(&sc, NULL, NULL), 0, "%s", sc.error);
	ATF_CHECK(sc.endpoint != NULL);
	oe_sysconf_free(&sc);

	/* The environment may name other files. */
	write_file("d.conf", "timeout_ms = 7;\n", 0644);
	write_file("l.conf", "compression = \"none\";\n", 0644);
	setenv("OTELCONF_DEFAULTS", "d.conf", 1);
	setenv("OTELCONF_FILE", "l.conf", 1);
	ATF_REQUIRE_EQ_MSG(oe_sysconf_load(&sc, NULL, NULL), 0, "%s",
	    sc.error);
	ATF_CHECK_EQ(sc.timeout_ms, 7);
	ATF_CHECK_STREQ(sc.compression, "none");
	oe_sysconf_free(&sc);
	/* Explicit arguments win over the environment. */
	ATF_REQUIRE_EQ(oe_sysconf_load(&sc, "", ""), 0);
	ATF_CHECK_EQ(sc.timeout_ms, OE_SYSCONF_DEFAULT_TIMEOUT_MS);
	oe_sysconf_free(&sc);
	unsetenv("OTELCONF_DEFAULTS");
	unsetenv("OTELCONF_FILE");
}

ATF_TC_WITHOUT_HEAD(missing_files);
ATF_TC_BODY(missing_files, tc)
{
	struct oe_sysconf sc;

	ATF_REQUIRE_EQ(oe_sysconf_load(&sc, "nonexistent.defaults",
	    "nonexistent.conf"), 0);
	ATF_CHECK_STREQ(sc.endpoint, OE_SYSCONF_DEFAULT_ENDPOINT);
	oe_sysconf_free(&sc);
}

ATF_TC_WITHOUT_HEAD(layering);
ATF_TC_BODY(layering, tc)
{
	struct oe_sysconf sc;

	write_file("hostid", "0f9a6c1e-1111-2222-3333-444455556666\n", 0644);
	write_file("defaults.conf",
	    "enable = true;\n"
	    "endpoint = \"http://localhost:4318\";\n"
	    "compression = \"gzip\";\n"
	    "timeout_ms = 10000;\n"
	    "host_id_file = \"" "/nonexistent/hostid" "\";\n"
	    "resource {\n"
	    "  \"service.namespace\" = \"5bsd\";\n"
	    "  \"deployment.environment.name\" = \"production\";\n"
	    "  \"keep.me\" = \"yes\";\n"
	    "}\n"
	    "spool { directory = \"/var/spool/otel\"; max_bytes = 2mb; }\n",
	    0644);
	write_file("local.conf",
	    "endpoint = \"https://collector.example:4318/otlp\";\n"
	    "compression = none;\n"
	    "timeout_ms = 2500;\n"
	    "resource {\n"
	    "  \"deployment.environment.name\" = \"staging\";\n"
	    "  \"service.namespace\" = \"\";\n"
	    "  \"team\" = \"infra\";\n"
	    "}\n"
	    "spool { max_bytes = 1048576; directory = \"/var/db/otel\"; }\n",
	    0644);
	ATF_REQUIRE_EQ_MSG(oe_sysconf_load(&sc, "defaults.conf",
	    "local.conf"), 0, "%s", sc.error);
	ATF_CHECK_STREQ(sc.endpoint, "https://collector.example:4318/otlp");
	ATF_CHECK_STREQ(sc.compression, "none");
	ATF_CHECK_EQ(sc.timeout_ms, 2500);
	ATF_CHECK_EQ(sc.nresource_attrs, 3);
	ATF_CHECK(attr(sc.resource_attrs, sc.nresource_attrs,
	    "service.namespace") == NULL);
	ATF_CHECK_STREQ(attr(sc.resource_attrs, sc.nresource_attrs,
	    "deployment.environment.name"), "staging");
	ATF_CHECK_STREQ(attr(sc.resource_attrs, sc.nresource_attrs,
	    "keep.me"), "yes");
	ATF_CHECK_STREQ(attr(sc.resource_attrs, sc.nresource_attrs,
	    "team"), "infra");
	ATF_CHECK_STREQ(sc.spool_dir, "/var/db/otel");
	ATF_CHECK_EQ(sc.spool_max_bytes, 1048576);
	oe_sysconf_free(&sc);
}

ATF_TC_WITHOUT_HEAD(disable_switch);
ATF_TC_BODY(disable_switch, tc)
{
	struct oe_sysconf sc;

	write_file("local.conf", "enable = false;\n", 0644);
	ATF_REQUIRE_EQ(oe_sysconf_load(&sc, "", "local.conf"), 0);
	ATF_CHECK_EQ(sc.enable, 0);
	oe_sysconf_free(&sc);
}

ATF_TC_WITHOUT_HEAD(malformed);
ATF_TC_BODY(malformed, tc)
{

	expect_error("endpoint = \"http://x\"\nresource {", "syntax error");
	expect_error("[1, 2]", "top level must be an object");
	expect_error("bogus = 1;", "unknown key bogus");
	expect_error("endpoint = 5;", "endpoint must be a single string");
	expect_error("endpoint = \"http://a\"; endpoint = \"http://b\";",
	    "endpoint must be a single string");
	expect_error("endpoint = \"ftp://host\";", "is not an http");
	expect_error("protocol = \"grpc\";", "implements only");
	expect_error("protocol = \"http/protobuf\";", "implements only");
	expect_error("protocol = \"carrier-pigeon\";", "is not supported");
	expect_error("protocol = 7;", "protocol must be a single string");
	expect_error("compression = \"zstd\";", "is not supported");
	expect_error("timeout_ms = 0;", "outside 1..600000");
	expect_error("timeout_ms = 600001;", "outside");
	expect_error("timeout_ms = \"10\";", "must be an integer");
	expect_error("enable = \"yes\";", "must be true or false");
	expect_error("headers_file = \"relative/path\";",
	    "must be an absolute path");
	expect_error("host_id_file = 1;", "must be a single string");
	expect_error("resource = 1;", "resource must be an object");
	expect_error("resource { \"bad key!\" = \"x\"; }",
	    "invalid resource attribute name");
	expect_error("resource { \"k\" = 1; }", "k must be a single string");
	expect_error("spool = \"x\";", "spool must be an object");
	expect_error("spool { directory = \"\"; }", "must not be empty");
	expect_error("spool { directory = 1; }", "must be a single string");
	expect_error("spool { max_bytes = 1000; }", "outside");
	expect_error("spool { max_bytes = \"x\"; }", "must be an integer");
	expect_error("spool { size = 1; }", "unknown key spool.size");
	expect_error("export = 1;", "export must be an object");
	expect_error("export { target = \"grpc\"; }",
	    "must be \"otlp\" or \"file\"");
	expect_error("export { target = 1; }", "must be a single string");
	expect_error("export { directory = \"rel\"; }", "absolute path");
	expect_error("export { directory = \"\"; }", "must not be empty");
	expect_error("export { rotate = 1; }", "unknown key export.rotate");
	/* The local agent and its keys are gone. */
	expect_error("agent = 1;", "unknown key agent");
	expect_error("agent { upstream = \"http://c:4318\"; }",
	    "unknown key agent");
	expect_error("endpoint = \"http://a\\u0000b\";", "NUL byte");
	expect_error("resource { \"\" = \"x\"; }", "syntax error");
}

ATF_TC_WITHOUT_HEAD(accepted_forms);
ATF_TC_BODY(accepted_forms, tc)
{
	struct oe_sysconf sc;

	/* The export block, layered key by key. */
	write_file("d.conf", "export { target = \"file\"; "
	    "directory = \"/var/db/o\"; }\n", 0644);
	write_file("l.conf", "export { directory = \"/srv/otel\"; }\n", 0644);
	ATF_REQUIRE_EQ_MSG(oe_sysconf_load(&sc, "d.conf", "l.conf"), 0, "%s",
	    sc.error);
	ATF_CHECK_EQ(sc.export_file, 1);
	ATF_CHECK_STREQ(sc.export_dir, "/srv/otel");
	oe_sysconf_free(&sc);
	write_file("l.conf", "export { target = \"otlp\"; }\n", 0644);
	ATF_REQUIRE_EQ(oe_sysconf_load(&sc, "d.conf", "l.conf"), 0);
	ATF_CHECK_EQ(sc.export_file, 0);
	oe_sysconf_free(&sc);

	/* Empty file, explicit protocol, an explicitly empty endpoint. */
	write_file("empty.conf", "", 0644);
	write_file("local.conf", "protocol = \"http/json\";\n"
	    "endpoint = \"\";\n", 0644);
	ATF_REQUIRE_EQ_MSG(oe_sysconf_load(&sc, "empty.conf", "local.conf"), 0,
	    "%s", sc.error);
	ATF_CHECK_STREQ(sc.protocol, "http/json");
	ATF_CHECK_STREQ(sc.endpoint, "");
	oe_sysconf_free(&sc);
}

ATF_TC_WITHOUT_HEAD(oversized_values);
ATF_TC_BODY(oversized_values, tc)
{
	char *text, *big;

	big = malloc(OE_SYSCONF_VALUE_MAX + 2);
	ATF_REQUIRE(big != NULL);
	memset(big, 'a', OE_SYSCONF_VALUE_MAX + 1);
	big[OE_SYSCONF_VALUE_MAX + 1] = '\0';
	ATF_REQUIRE(asprintf(&text, "resource { k = \"%s\"; }", big) > 0);
	expect_error(text, "longer than");
	free(text);
	big[OE_SYSCONF_KEY_MAX + 1] = '\0';
	ATF_REQUIRE(asprintf(&text, "resource { %s = \"v\"; }", big) > 0);
	expect_error(text, "invalid resource attribute name");
	free(text);
	free(big);
}

ATF_TC_WITHOUT_HEAD(too_many_attrs);
ATF_TC_BODY(too_many_attrs, tc)
{
	char text[8192];
	size_t len;
	int i;

	len = strlcpy(text, "resource {\n", sizeof(text));
	for (i = 0; i <= OE_SYSCONF_ATTRS_MAX; i++)
		len += snprintf(text + len, sizeof(text) - len,
		    "  a%d = \"v\";\n", i);
	strlcat(text, "}\n", sizeof(text));
	expect_error(text, "too many resource attributes");
}

ATF_TC_WITHOUT_HEAD(file_faults);
ATF_TC_BODY(file_faults, tc)
{
	struct oe_sysconf sc;
	char *big;
	int fd;

	/* Group-writable configuration is refused. */
	write_file("gw.conf", "enable = true;\n", 0664);
	ATF_CHECK_EQ(oe_sysconf_load(&sc, "", "gw.conf"), -1);
	ATF_CHECK(strstr(sc.error, "writable by group or others") != NULL);
	oe_sysconf_free(&sc);

	/* Symbolic links are refused, even to a good file. */
	write_file("good.conf", "enable = true;\n", 0644);
	ATF_REQUIRE(symlink("good.conf", "link.conf") == 0);
	ATF_CHECK_EQ(oe_sysconf_load(&sc, "link.conf", ""), -1);
	ATF_CHECK(strstr(sc.error, "symbolic links are refused") != NULL);
	oe_sysconf_free(&sc);

	/* A looping path component reports ELOOP. */
	ATF_REQUIRE(symlink("loop2", "loop1") == 0);
	ATF_REQUIRE(symlink("loop1", "loop2") == 0);
	ATF_CHECK_EQ(oe_sysconf_load(&sc, "", "loop1/x.conf"), -1);
	ATF_CHECK(strstr(sc.error, "symbolic links are refused") != NULL);
	oe_sysconf_free(&sc);

	/* Directories and FIFOs are not regular files. */
	ATF_REQUIRE(mkdir("dir.conf", 0755) == 0);
	ATF_CHECK_EQ(oe_sysconf_load(&sc, "", "dir.conf"), -1);
	ATF_CHECK(strstr(sc.error, "not a regular file") != NULL);
	oe_sysconf_free(&sc);
	ATF_REQUIRE(mkfifo("fifo.conf", 0644) == 0);
	ATF_CHECK_EQ(oe_sysconf_load(&sc, "", "fifo.conf"), -1);
	ATF_CHECK(strstr(sc.error, "not a regular file") != NULL);
	oe_sysconf_free(&sc);

	/* Oversized files are refused before parsing. */
	big = malloc(OE_SYSCONF_FILE_MAX + 2);
	ATF_REQUIRE(big != NULL);
	memset(big, '#', OE_SYSCONF_FILE_MAX + 1);
	big[OE_SYSCONF_FILE_MAX + 1] = '\0';
	write_file("big.conf", big, 0644);
	free(big);
	ATF_CHECK_EQ(oe_sysconf_load(&sc, "", "big.conf"), -1);
	ATF_CHECK(strstr(sc.error, "byte limit") != NULL);
	oe_sysconf_free(&sc);

	/* Embedded NUL bytes are refused. */
	fd = open("nul.conf", O_WRONLY | O_CREAT | O_TRUNC, 0644);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(write(fd, "enable = true;\0x", 16) == 16);
	close(fd);
	ATF_CHECK_EQ(oe_sysconf_load(&sc, "", "nul.conf"), -1);
	ATF_CHECK(strstr(sc.error, "NUL byte") != NULL);
	oe_sysconf_free(&sc);

	/* An unreadable path component is reported, not ignored. */
	ATF_CHECK_EQ(oe_sysconf_load(&sc, "", "good.conf/child"), -1);
	ATF_CHECK(strstr(sc.error, "good.conf/child") != NULL);
	oe_sysconf_free(&sc);
}

ATF_TC(wrong_owner);
ATF_TC_HEAD(wrong_owner, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(wrong_owner, tc)
{
	struct oe_sysconf sc;
	struct oe_attr *h;
	struct passwd *pw;
	char err[256];
	size_t n;

	pw = getpwnam("nobody");
	ATF_REQUIRE(pw != NULL);
	write_file("other.conf", "enable = true;\n", 0644);
	ATF_REQUIRE(chown("other.conf", pw->pw_uid, pw->pw_gid) == 0);
	ATF_CHECK_EQ(oe_sysconf_load(&sc, "", "other.conf"), -1);
	ATF_CHECK(strstr(sc.error, "must be owned by root") != NULL);
	oe_sysconf_free(&sc);

	write_file("other.headers", "Authorization: Bearer x\n", 0600);
	ATF_REQUIRE(chown("other.headers", pw->pw_uid, pw->pw_gid) == 0);
	ATF_CHECK_EQ(oe_headers_file_load("other.headers", &h, &n, err,
	    sizeof(err)), -1);
	ATF_CHECK(strstr(err, "must be owned by root") != NULL);
}

ATF_TC_WITHOUT_HEAD(headers_file);
ATF_TC_BODY(headers_file, tc)
{
	struct oe_sysconf sc;
	char conf[512], cwd[256];

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	write_file("creds",
	    "# collector credentials\n"
	    "\n"
	    "Authorization:  Bearer s3cr3t  \r\n"
	    "  X-Scope-OrgID:tenant-1\n"
	    "x-scope-orgid: tenant-2\n"
	    "\tX-Tab \t:\tvalue\twith tab\t", 0600);
	snprintf(conf, sizeof(conf), "headers_file = \"%s/creds\";\n", cwd);
	write_file("local.conf", conf, 0644);
	ATF_REQUIRE_EQ_MSG(oe_sysconf_load(&sc, "", "local.conf"), 0, "%s",
	    sc.error);
	ATF_REQUIRE_EQ(sc.nheaders, 4);
	ATF_CHECK_STREQ(attr(sc.headers, sc.nheaders, "Authorization"),
	    "Bearer s3cr3t");
	ATF_CHECK_STREQ(attr(sc.headers, sc.nheaders, "X-Scope-OrgID"),
	    "tenant-1");
	ATF_CHECK_STREQ(attr(sc.headers, sc.nheaders, "x-scope-orgid"),
	    "tenant-2");
	ATF_CHECK_STREQ(attr(sc.headers, sc.nheaders, "X-Tab"),
	    "value\twith tab");
	oe_sysconf_free(&sc);

	/* 0400 is fine as well. */
	ATF_REQUIRE(chmod("creds", 0400) == 0);
	ATF_REQUIRE_EQ(oe_sysconf_load(&sc, "", "local.conf"), 0);
	oe_sysconf_free(&sc);

	/* Group or other access to credentials is refused. */
	ATF_REQUIRE(chmod("creds", 0640) == 0);
	ATF_CHECK_EQ(oe_sysconf_load(&sc, "", "local.conf"), -1);
	ATF_CHECK_MSG(strstr(sc.error, "mode 0640") != NULL &&
	    strstr(sc.error, "use mode 0600") != NULL, "%s", sc.error);
	ATF_CHECK_EQ(sc.nheaders, 0);
	oe_sysconf_free(&sc);
	ATF_REQUIRE(chmod("creds", 0604) == 0);
	ATF_CHECK_EQ(oe_sysconf_load(&sc, "", "local.conf"), -1);
	oe_sysconf_free(&sc);

	/* A configured but missing credentials file is an error. */
	ATF_REQUIRE(unlink("creds") == 0);
	ATF_CHECK_EQ(oe_sysconf_load(&sc, "", "local.conf"), -1);
	ATF_CHECK(strstr(sc.error, "headers file does not exist") != NULL);
	oe_sysconf_free(&sc);
}

static void
expect_headers_error(const char *text, const char *needle)
{
	struct oe_attr *h;
	char err[256];
	size_t n;

	write_file("h", text, 0600);
	ATF_CHECK_EQ_MSG(oe_headers_file_load("h", &h, &n, err, sizeof(err)),
	    -1, "accepted: %s", text);
	ATF_CHECK_MSG(strstr(err, needle) != NULL, "error \"%s\" lacks "
	    "\"%s\"", err, needle);
	ATF_CHECK(h == NULL && n == 0);
}

ATF_TC_WITHOUT_HEAD(headers_faults);
ATF_TC_BODY(headers_faults, tc)
{
	char text[4096], *big;
	size_t len;
	int i;

	expect_headers_error("Authorization Bearer x\n", ":1: expected");
	expect_headers_error("\n\nBad Name: x\n", ":3: invalid header name");
	expect_headers_error(": x\n", "invalid header name");
	expect_headers_error("Empty:   \n", "invalid or empty header value");
	expect_headers_error("Ctl: a\x01b\n", "invalid or empty");
	expect_headers_error("Del: a\x7f\n", "invalid or empty");
	expect_headers_error("Content-Type: text/plain\n", "set by the "
	    "exporter");
	expect_headers_error("content-length: 1\n", "set by the exporter");
	expect_headers_error("Content-Encoding: br\n", "set by the exporter");
	expect_headers_error("Host: evil\n", "set by the exporter");
	expect_headers_error("Connection: keep-alive\n", "set by the "
	    "exporter");
	len = 0;
	text[0] = '\0';
	for (i = 0; i <= OE_SYSCONF_HEADERS_MAX; i++)
		len += snprintf(text + len, sizeof(text) - len, "H%d: v\n", i);
	expect_headers_error(text, "too many headers");

	big = malloc(OE_SYSCONF_VALUE_MAX + 16);
	ATF_REQUIRE(big != NULL);
	memcpy(big, "Long: ", 6);
	memset(big + 6, 'v', OE_SYSCONF_VALUE_MAX + 1);
	big[OE_SYSCONF_VALUE_MAX + 7] = '\0';
	expect_headers_error(big, "invalid or empty");
	free(big);

	big = malloc(OE_SYSCONF_KEY_MAX + 16);
	ATF_REQUIRE(big != NULL);
	memset(big, 'k', OE_SYSCONF_KEY_MAX + 1);
	memcpy(big + OE_SYSCONF_KEY_MAX + 1, ": v\n", 5);
	expect_headers_error(big, "invalid header name");
	free(big);

	big = malloc(OE_SYSCONF_HEADERS_FILE_MAX + 2);
	ATF_REQUIRE(big != NULL);
	memset(big, '#', OE_SYSCONF_HEADERS_FILE_MAX + 1);
	big[OE_SYSCONF_HEADERS_FILE_MAX + 1] = '\0';
	expect_headers_error(big, "byte limit");
	free(big);
}

ATF_TC_WITHOUT_HEAD(host_id);
ATF_TC_BODY(host_id, tc)
{
	struct oe_sysconf sc;
	char conf[512], cwd[256];

	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	snprintf(conf, sizeof(conf), "host_id_file = \"%s/hostid\";\n", cwd);
	write_file("local.conf", conf, 0644);

	write_file("hostid", "0F9A6C1E-1111-2222-3333-444455556666\n", 0644);
	ATF_REQUIRE_EQ(oe_sysconf_load(&sc, "", "local.conf"), 0);
	ATF_CHECK_STREQ(attr(sc.resource_attrs, sc.nresource_attrs,
	    "host.id"), "0F9A6C1E-1111-2222-3333-444455556666");
	oe_sysconf_free(&sc);

	/* No host ID yet (first boot): the attribute is simply absent. */
	ATF_REQUIRE(unlink("hostid") == 0);
	ATF_REQUIRE_EQ(oe_sysconf_load(&sc, "", "local.conf"), 0);
	ATF_CHECK(attr(sc.resource_attrs, sc.nresource_attrs, "host.id") ==
	    NULL);
	oe_sysconf_free(&sc);

	write_file("hostid", "not a uuid\n", 0644);
	ATF_CHECK_EQ(oe_sysconf_load(&sc, "", "local.conf"), -1);
	ATF_CHECK(strstr(sc.error, "does not contain a host UUID") != NULL);
	oe_sysconf_free(&sc);
	write_file("hostid", "\n", 0644);
	ATF_CHECK_EQ(oe_sysconf_load(&sc, "", "local.conf"), -1);
	oe_sysconf_free(&sc);
	write_file("hostid", "0123456789012345678901234567890123456789"
	    "01234567890123456789012345", 0644);
	ATF_CHECK_EQ(oe_sysconf_load(&sc, "", "local.conf"), -1);
	oe_sysconf_free(&sc);
	write_file("hostid", "abc\n", 0666);
	ATF_CHECK_EQ(oe_sysconf_load(&sc, "", "local.conf"), -1);
	ATF_CHECK(strstr(sc.error, "writable") != NULL);
	oe_sysconf_free(&sc);

	/* An explicit resource attribute wins over the file. */
	snprintf(conf, sizeof(conf), "host_id_file = \"%s/hostid\";\n"
	    "resource { \"host.id\" = \"pinned\"; }\n", cwd);
	write_file("local.conf", conf, 0644);
	ATF_REQUIRE_EQ(oe_sysconf_load(&sc, "", "local.conf"), 0);
	ATF_CHECK_STREQ(attr(sc.resource_attrs, sc.nresource_attrs,
	    "host.id"), "pinned");
	oe_sysconf_free(&sc);

	/* "" disables the lookup. */
	write_file("local.conf", "host_id_file = \"\";\n", 0644);
	ATF_REQUIRE_EQ(oe_sysconf_load(&sc, "", "local.conf"), 0);
	ATF_CHECK(attr(sc.resource_attrs, sc.nresource_attrs, "host.id") ==
	    NULL);
	oe_sysconf_free(&sc);
}

ATF_TC_WITHOUT_HEAD(env_layering);
ATF_TC_BODY(env_layering, tc)
{
	struct oe_sysconf sc;
	struct oe_env env;
	char conf[512], cwd[256];

	clear_env();
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	write_file("creds", "Authorization: Bearer system\n", 0600);
	snprintf(conf, sizeof(conf),
	    "endpoint = \"http://collector:4318\";\n"
	    "compression = \"none\";\n"
	    "timeout_ms = 1234;\n"
	    "host_id_file = \"\";\n"
	    "headers_file = \"%s/creds\";\n"
	    "resource { \"service.namespace\" = \"sys\"; \"a\" = \"1\"; }\n",
	    cwd);
	write_file("local.conf", conf, 0644);
	ATF_REQUIRE_EQ_MSG(oe_sysconf_load(&sc, "", "local.conf"), 0, "%s",
	    sc.error);

	/* System layer fills everything the environment left unset. */
	ATF_REQUIRE_EQ(oe_env_load_system(&env, &sc, NULL), 0);
	ATF_CHECK_STREQ(env.endpoint, "http://collector:4318");
	ATF_CHECK_STREQ(env.compression, "none");
	ATF_CHECK_EQ(env.timeout_ms, 1234);
	ATF_CHECK_EQ(env.nresource_attrs, 2);
	ATF_CHECK_STREQ(attr(env.headers, env.nheaders, "Authorization"),
	    "Bearer system");
	oe_env_free(&env);

	/* Environment wins key by key. */
	setenv("OTEL_EXPORTER_OTLP_COMPRESSION", "gzip", 1);
	setenv("OTEL_EXPORTER_OTLP_TIMEOUT", "50", 1);
	setenv("OTEL_RESOURCE_ATTRIBUTES", "service.namespace=env,b=2", 1);
	setenv("OTEL_EXPORTER_OTLP_HEADERS", "Authorization=Bearer env", 1);
	ATF_REQUIRE_EQ(oe_env_load_system(&env, &sc, NULL), 0);
	ATF_CHECK_STREQ(env.compression, "gzip");
	ATF_CHECK_EQ(env.timeout_ms, 50);
	ATF_CHECK_EQ(env.nresource_attrs, 3);
	ATF_CHECK_STREQ(attr(env.resource_attrs, env.nresource_attrs,
	    "service.namespace"), "env");
	ATF_CHECK_STREQ(attr(env.resource_attrs, env.nresource_attrs, "a"),
	    "1");
	ATF_CHECK_EQ(env.nheaders, 1);
	ATF_CHECK_STREQ(attr(env.headers, env.nheaders, "Authorization"),
	    "Bearer env");
	oe_env_free(&env);
	clear_env();

	/* System credentials never follow an endpoint chosen elsewhere. */
	setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://elsewhere:4318", 1);
	ATF_REQUIRE_EQ(oe_env_load_system(&env, &sc, NULL), 0);
	ATF_CHECK_STREQ(env.endpoint, "http://elsewhere:4318");
	ATF_CHECK_EQ(env.nheaders, 0);
	ATF_CHECK_EQ(env.nresource_attrs, 2);
	oe_env_free(&env);
	clear_env();
	ATF_REQUIRE_EQ(oe_env_load_system(&env, &sc, "http://cli:1"), 0);
	ATF_CHECK_STREQ(env.endpoint, "http://cli:1");
	ATF_CHECK_EQ(env.nheaders, 0);
	oe_env_free(&env);

	/* The command line beats the environment. */
	setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://elsewhere:4318", 1);
	ATF_REQUIRE_EQ(oe_env_load_system(&env, &sc, "http://cli:1"), 0);
	ATF_CHECK_STREQ(env.endpoint, "http://cli:1");
	oe_env_free(&env);
	clear_env();

	/*
	 * An empty system endpoint is unset: no endpoint, and the system
	 * credentials go nowhere.
	 */
	free(sc.endpoint);
	sc.endpoint = strdup("");
	ATF_REQUIRE(sc.endpoint != NULL);
	ATF_REQUIRE_EQ(oe_env_load_system(&env, &sc, NULL), 0);
	ATF_CHECK(env.endpoint == NULL);
	ATF_CHECK_EQ(env.nheaders, 0);
	ATF_CHECK_EQ(env.timeout_ms, 1234);
	oe_env_free(&env);
	ATF_REQUIRE_EQ(oe_env_load_system(&env, &sc, "http://cli:1"), 0);
	ATF_CHECK_EQ(env.nheaders, 0);
	oe_env_free(&env);

	/* A disabled or absent system layer contributes nothing. */
	sc.enable = 0;
	ATF_REQUIRE_EQ(oe_env_load_system(&env, &sc, NULL), 0);
	ATF_CHECK(env.endpoint == NULL);
	ATF_CHECK_EQ(env.timeout_ms, -1);
	ATF_CHECK_EQ(env.nresource_attrs, 0);
	oe_env_free(&env);
	ATF_REQUIRE_EQ(oe_env_load_system(&env, NULL, NULL), 0);
	ATF_CHECK(env.endpoint == NULL);
	oe_env_free(&env);
	oe_sysconf_free(&sc);
}

/* oe_config_load(): every layer, the system spool and its failures. */
ATF_TC_WITHOUT_HEAD(config_load);
ATF_TC_BODY(config_load, tc)
{
	struct oe_config_request req;
	struct oe_env env;
	struct oe_resource r;
	struct oe_host_info hi;
	struct oe_otlp_config cfg;
	char conf[768], cwd[256], err[600], path[512];

	clear_env();
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	ATF_REQUIRE(mkdir("spool", 0700) == 0);
	snprintf(conf, sizeof(conf),
	    "endpoint = \"http://collector:4318\";\n"
	    "timeout_ms = 2500;\n"
	    "host_id_file = \"\";\n"
	    "resource { \"service.name\" = \"fromconf\"; \"a\" = \"1\"; }\n"
	    "spool { directory = \"%s/spool\"; max_bytes = 2097152; }\n",
	    cwd);
	write_file("local.conf", conf, 0644);
	setenv("OTELCONF_DEFAULTS", "", 1);
	setenv("OTELCONF_FILE", "local.conf", 1);

	memset(&req, 0, sizeof(req));
	req.scope = "tool";
	req.system = 1;
	ATF_REQUIRE_EQ_MSG(oe_config_load(&env, &req, err, sizeof(err)), 0,
	    "%s", err);
	ATF_REQUIRE(env.sysconf != NULL);
	ATF_CHECK_STREQ(env.endpoint, "http://collector:4318");
	ATF_CHECK_EQ(env.endpoint_default, 0);
	ATF_CHECK_EQ(env.timeout_ms, 2500);
	snprintf(path, sizeof(path), "%s/spool/tool.spool", cwd);
	ATF_CHECK_STREQ(env.spool_path, path);
	ATF_CHECK_EQ(env.spool_max, 2097152);
	ATF_CHECK_EQ(env.spool_optional, 1);

	/* The resource: service.name from the attributes, then defaults. */
	memset(&hi, 0, sizeof(hi));
	strlcpy(hi.host_name, "h", sizeof(hi.host_name));
	oe_resource_init(&r, &env, &hi, "tool", "9.9");
	ATF_CHECK_STREQ(r.service_name, "fromconf");
	ATF_CHECK_STREQ(r.service_version, "9.9");
	ATF_CHECK_STREQ(r.host_name, "h");
	ATF_CHECK_EQ(r.ncustom, 2);
	setenv("OTEL_SERVICE_NAME", "fromenv", 1);
	oe_env_free(&env);
	ATF_REQUIRE_EQ(oe_config_load(&env, &req, err, sizeof(err)), 0);
	oe_resource_init(&r, &env, &hi, "tool", "9.9");
	ATF_CHECK_STREQ(r.service_name, "fromenv");

	/* The OTLP configuration carries every resolved setting. */
	memset(&cfg, 0, sizeof(cfg));
	oe_otlp_config_env(&cfg, &env);
	ATF_CHECK_STREQ(cfg.endpoint, "http://collector:4318");
	ATF_CHECK(cfg.timeout == 2.5);
	ATF_CHECK_STREQ(cfg.spool_path, path);
	ATF_CHECK_EQ(cfg.spool_max, 2097152);
	ATF_CHECK_EQ(cfg.spool_optional, 1);
	oe_env_free(&env);
	clear_env();

	/* Command line endpoint and spool win; the bound still layers. */
	req.endpoint = "http://cli:1";
	req.spool = "mine.spool";
	ATF_REQUIRE_EQ(oe_config_load(&env, &req, err, sizeof(err)), 0);
	ATF_CHECK_STREQ(env.endpoint, "http://cli:1");
	ATF_CHECK_STREQ(env.spool_path, "mine.spool");
	ATF_CHECK_EQ(env.spool_max, 2097152);
	ATF_CHECK_EQ(env.spool_optional, 0);
	oe_env_free(&env);
	req.spool_max = 4096;
	ATF_REQUIRE_EQ(oe_config_load(&env, &req, err, sizeof(err)), 0);
	ATF_CHECK_EQ(env.spool_max, 4096);
	oe_env_free(&env);
	req.endpoint = NULL;
	req.spool = NULL;
	/* A command line bound applies to the system spool too. */
	ATF_REQUIRE_EQ(oe_config_load(&env, &req, err, sizeof(err)), 0);
	ATF_CHECK_STREQ(env.spool_path, path);
	ATF_CHECK_EQ(env.spool_max, 4096);
	oe_env_free(&env);
	req.spool_max = 0;

	/* An unwritable spool directory means no system spool. */
	ATF_REQUIRE(chmod("spool", 0500) == 0);
	if (access("spool", W_OK) != 0) {
		ATF_REQUIRE_EQ(oe_config_load(&env, &req, err, sizeof(err)),
		    0);
		ATF_CHECK(env.spool_path == NULL);
		oe_env_free(&env);
	}
	ATF_REQUIRE(chmod("spool", 0700) == 0);

	/* Without the system layer: environment, then the default. */
	req.system = 0;
	ATF_REQUIRE_EQ(oe_config_load(&env, &req, err, sizeof(err)), 0);
	ATF_CHECK(env.sysconf == NULL);
	ATF_CHECK_STREQ(env.endpoint, OE_DEFAULT_ENDPOINT);
	ATF_CHECK_EQ(env.endpoint_default, 1);
	ATF_CHECK(env.spool_path == NULL);
	memset(&cfg, 0, sizeof(cfg));
	oe_otlp_config_env(&cfg, &env);
	ATF_CHECK_STREQ(cfg.endpoint, OE_DEFAULT_ENDPOINT);
	ATF_CHECK(cfg.timeout == 0);
	oe_env_free(&env);
	/* oe_otlp_config_env() on bare environment settings. */
	oe_env_load(&env);
	oe_otlp_config_env(&cfg, &env);
	ATF_CHECK_STREQ(cfg.endpoint, OE_DEFAULT_ENDPOINT);
	oe_env_free(&env);
	req.spool = "cli.spool";
	ATF_REQUIRE_EQ(oe_config_load(&env, &req, err, sizeof(err)), 0);
	ATF_CHECK_EQ(env.spool_max, 0);
	oe_env_free(&env);
	req.spool = NULL;
	req.system = 1;

	/* A disabled system layer contributes nothing, not even a spool. */
	write_file("local.conf", "enable = false;\n"
	    "endpoint = \"http://collector:4318\";\n", 0644);
	ATF_REQUIRE_EQ(oe_config_load(&env, &req, err, sizeof(err)), 0);
	ATF_CHECK_STREQ(env.endpoint, OE_DEFAULT_ENDPOINT);
	ATF_CHECK(env.spool_path == NULL);
	ATF_CHECK(env.sysconf != NULL && !env.sysconf->enable);
	oe_env_free(&env);

	/*
	 * An enabled layer without an endpoint (the shipped default) leaves
	 * the conventional default to programs run by hand, and says so.
	 */
	write_file("local.conf", "endpoint = \"\";\n", 0644);
	ATF_REQUIRE_EQ(oe_config_load(&env, &req, err, sizeof(err)), 0);
	ATF_CHECK_STREQ(env.endpoint, OE_DEFAULT_ENDPOINT);
	ATF_CHECK_EQ(env.endpoint_default, 1);
	oe_env_free(&env);
	setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://env:1", 1);
	ATF_REQUIRE_EQ(oe_config_load(&env, &req, err, sizeof(err)), 0);
	ATF_CHECK_STREQ(env.endpoint, "http://env:1");
	ATF_CHECK_EQ(env.endpoint_default, 0);
	oe_env_free(&env);
	clear_env();

	/*
	 * The file target: one file per tool, no spool, and the system
	 * endpoint unused; the command line or the environment still
	 * choose OTLP/HTTP.
	 */
	write_file("local.conf", "endpoint = \"http://collector:4318\";\n"
	    "export { target = \"file\"; directory = \"/var/log/x\"; }\n"
	    "spool { directory = \"/tmp\"; }\n", 0644);
	ATF_REQUIRE_EQ_MSG(oe_config_load(&env, &req, err, sizeof(err)), 0,
	    "%s", err);
	ATF_CHECK_STREQ(env.file_path, "/var/log/x/tool.jsonl");
	ATF_CHECK(env.spool_path == NULL);
	ATF_CHECK_EQ(env.endpoint_default, 0);
	ATF_CHECK_STREQ(env.endpoint, OE_DEFAULT_ENDPOINT);
	oe_env_free(&env);
	ATF_CHECK(env.file_path == NULL && env.file_buf == NULL);
	req.spool = "cli.spool";
	ATF_REQUIRE_EQ(oe_config_load(&env, &req, err, sizeof(err)), 0);
	ATF_CHECK_STREQ(env.file_path, "/var/log/x/tool.jsonl");
	oe_env_free(&env);
	req.spool = NULL;
	req.endpoint = "http://cli:1";
	ATF_REQUIRE_EQ(oe_config_load(&env, &req, err, sizeof(err)), 0);
	ATF_CHECK(env.file_path == NULL);
	ATF_CHECK_STREQ(env.endpoint, "http://cli:1");
	oe_env_free(&env);
	req.endpoint = NULL;
	setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://env:1", 1);
	ATF_REQUIRE_EQ(oe_config_load(&env, &req, err, sizeof(err)), 0);
	ATF_CHECK(env.file_path == NULL);
	ATF_CHECK_STREQ(env.endpoint, "http://env:1");
	oe_env_free(&env);
	clear_env();
	/* Programs that do not read the system layer never see it. */
	req.system = 0;
	ATF_REQUIRE_EQ(oe_config_load(&env, &req, err, sizeof(err)), 0);
	ATF_CHECK(env.file_path == NULL);
	oe_env_free(&env);
	req.system = 1;
	/* Nor when it is disabled. */
	write_file("local.conf", "enable = false;\n"
	    "export { target = \"file\"; }\n", 0644);
	ATF_REQUIRE_EQ(oe_config_load(&env, &req, err, sizeof(err)), 0);
	ATF_CHECK(env.file_path == NULL);
	ATF_CHECK_EQ(env.endpoint_default, 1);
	oe_env_free(&env);

	/* An invalid otel.conf is an error, and env is left empty. */
	write_file("local.conf", "endpoint = 5;\n", 0644);
	ATF_REQUIRE_EQ(oe_config_load(&env, &req, err, sizeof(err)), -1);
	ATF_CHECK_MSG(strstr(err, "local.conf") != NULL, "%s", err);
	ATF_CHECK(env.endpoint == NULL && env.sysconf == NULL);
	oe_env_free(&env);
	unsetenv("OTELCONF_DEFAULTS");
	unsetenv("OTELCONF_FILE");
}

/* oe_service_open(): the services' path through oe_config_load(). */
ATF_TC_WITHOUT_HEAD(service_open);
ATF_TC_BODY(service_open, tc)
{
	struct oe_service svc;
	struct oe_event ev;
	struct stat st;
	char err[600], conf[600], cwd[256], path[512];

	clear_env();
	setenv("OTELCONF_DEFAULTS", "", 1);
	setenv("OTELCONF_FILE", "local.conf", 1);
	write_file("local.conf", "host_id_file = \"\";\n"
	    "spool { directory = \"/nonexistent/otel\"; }\n", 0644);
	ATF_REQUIRE_EQ_MSG(oe_service_open(&svc, "svc", "1.0", "prof",
	    "http://127.0.0.1:9", 1.0, NULL, err, sizeof(err)), 0, "%s", err);
	ATF_CHECK_STREQ(svc.resource.service_name, "svc");
	ATF_CHECK_STREQ(svc.env.endpoint, "http://127.0.0.1:9");
	ATF_CHECK(svc.env.spool_path == NULL);
	ATF_REQUIRE(svc.exporter != NULL);
	oe_service_close(&svc);

	/*
	 * No export target anywhere: a service never falls back to the
	 * conventional endpoint, where nothing in the base system listens.
	 */
	ATF_REQUIRE_EQ(oe_service_open(&svc, "svc", "1.0", "prof", NULL, 1.0,
	    NULL, err, sizeof(err)), -1);
	ATF_CHECK_MSG(strstr(err, "no export target") != NULL, "%s", err);
	ATF_CHECK(svc.exporter == NULL);
	oe_service_close(&svc);
	/* The environment names one. */
	setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:9", 1);
	ATF_REQUIRE_EQ_MSG(oe_service_open(&svc, "svc", "1.0", "prof", NULL,
	    1.0, NULL, err, sizeof(err)), 0, "%s", err);
	oe_service_close(&svc);
	clear_env();

	/* An unknown user is refused before any exporter exists. */
	ATF_REQUIRE_EQ(oe_service_open(&svc, "svc", "1.0", "prof",
	    "http://127.0.0.1:9", 1.0, "no-such-user-otel", err,
	    sizeof(err)), -1);
	ATF_CHECK_MSG(strstr(err, "unknown user") != NULL, "%s", err);
	ATF_CHECK(svc.exporter == NULL);
	oe_service_close(&svc);

	/* A bad endpoint fails exporter creation. */
	ATF_REQUIRE_EQ(oe_service_open(&svc, "svc", "1.0", "prof",
	    "notaurl", 1.0, NULL, err, sizeof(err)), -1);
	ATF_CHECK_MSG(strstr(err, "cannot create") != NULL, "%s", err);
	oe_service_close(&svc);

	write_file("local.conf", "enable = false;\n", 0644);
	ATF_REQUIRE_EQ(oe_service_open(&svc, "svc", "1.0", "prof", NULL, 1.0,
	    NULL, err, sizeof(err)), -1);
	ATF_CHECK_MSG(strstr(err, "disabled") != NULL, "%s", err);
	oe_service_close(&svc);

	/* The file target: OTLP JSON Lines written on oe_service_flush(). */
	ATF_REQUIRE(getcwd(cwd, sizeof(cwd)) != NULL);
	ATF_REQUIRE(mkdir("logs", 0750) == 0);
	snprintf(conf, sizeof(conf), "host_id_file = \"\";\n"
	    "export { target = \"file\"; directory = \"%s/logs\"; }\n", cwd);
	write_file("local.conf", conf, 0644);
	ATF_REQUIRE_EQ_MSG(oe_service_open(&svc, "svc", "1.0", "prof", NULL,
	    1.0, NULL, err, sizeof(err)), 0, "%s", err);
	snprintf(path, sizeof(path), "%s/logs/svc.jsonl", cwd);
	ATF_CHECK_STREQ(svc.env.file_path, path);
	memset(&ev, 0, sizeof(ev));
	clock_gettime(CLOCK_REALTIME, &ev.ts);
	ev.profile = "prof";
	ev.probe = "p";
	ev.execname = "";
	ev.body = "one record";
	ATF_REQUIRE_EQ(0, oe_event(svc.exporter, &ev));
	ATF_REQUIRE(stat(path, &st) == 0);
	ATF_CHECK_EQ(st.st_size, 0);
	ATF_REQUIRE_EQ(0, oe_service_flush(&svc));
	ATF_REQUIRE(stat(path, &st) == 0);
	ATF_CHECK(st.st_size > 0);
	ATF_CHECK_EQ(st.st_mode & ALLPERMS, OE_FILE_TARGET_MODE);
	oe_service_close(&svc);
	/* An unwritable directory fails the service. */
	snprintf(conf, sizeof(conf), "host_id_file = \"\";\n"
	    "export { target = \"file\"; directory = \"%s/nologs\"; }\n",
	    cwd);
	write_file("local.conf", conf, 0644);
	ATF_REQUIRE_EQ(oe_service_open(&svc, "svc", "1.0", "prof", NULL, 1.0,
	    NULL, err, sizeof(err)), -1);
	ATF_CHECK_MSG(strstr(err, "nologs/svc.jsonl") != NULL, "%s", err);
	oe_service_close(&svc);
	/* With OTLP/HTTP, oe_service_flush() leaves batching to it. */
	ATF_REQUIRE_EQ(oe_service_open(&svc, "svc", "1.0", "prof",
	    "http://127.0.0.1:9", 1.0, NULL, err, sizeof(err)), 0);
	ATF_CHECK_EQ(0, oe_service_flush(&svc));
	oe_service_close(&svc);
	memset(&svc, 0, sizeof(svc));
	ATF_CHECK_EQ(0, oe_service_flush(&svc));

	write_file("local.conf", "bogus = 1;\n", 0644);
	ATF_REQUIRE_EQ(oe_service_open(&svc, "svc", "1.0", "prof", NULL, 1.0,
	    NULL, err, sizeof(err)), -1);
	ATF_CHECK_MSG(strstr(err, "bogus") != NULL, "%s", err);
	oe_service_close(&svc);
	unsetenv("OTELCONF_DEFAULTS");
	unsetenv("OTELCONF_FILE");
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, builtin_defaults);
	ATF_TP_ADD_TC(tp, standard_paths);
	ATF_TP_ADD_TC(tp, missing_files);
	ATF_TP_ADD_TC(tp, layering);
	ATF_TP_ADD_TC(tp, disable_switch);
	ATF_TP_ADD_TC(tp, malformed);
	ATF_TP_ADD_TC(tp, accepted_forms);
	ATF_TP_ADD_TC(tp, oversized_values);
	ATF_TP_ADD_TC(tp, too_many_attrs);
	ATF_TP_ADD_TC(tp, file_faults);
	ATF_TP_ADD_TC(tp, wrong_owner);
	ATF_TP_ADD_TC(tp, headers_file);
	ATF_TP_ADD_TC(tp, headers_faults);
	ATF_TP_ADD_TC(tp, host_id);
	ATF_TP_ADD_TC(tp, env_layering);
	ATF_TP_ADD_TC(tp, config_load);
	ATF_TP_ADD_TC(tp, service_open);
	return (atf_no_error());
}
