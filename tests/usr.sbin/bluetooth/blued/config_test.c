/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF unit tests for blued configuration parsing.
 */

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include <sys/types.h>

#include <atf-c.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "att.h"
#include "att_server.h"
#include "config.h"
#include "smp.h"

/*
 * Every fixture this suite writes goes into a per-process temporary directory
 * created with mkdtemp(3) under $TMPDIR (or /tmp), addressed with an absolute
 * path.  Nothing is ever written to the current working directory, so a test
 * run -- whether under kyua or standalone from any cwd -- leaves the source
 * tree byte-for-byte clean.  The directory and everything in it is removed at
 * process exit on a best-effort basis (cleanup errors never fail a test).
 */
static char cfg_tmpdir_path[PATH_MAX];

static void
cfg_tmpdir_cleanup(void)
{
	DIR *d;
	struct dirent *e;
	char p[PATH_MAX];

	if (cfg_tmpdir_path[0] == '\0')
		return;
	d = opendir(cfg_tmpdir_path);
	if (d != NULL) {
		while ((e = readdir(d)) != NULL) {
			if (strcmp(e->d_name, ".") == 0 ||
			    strcmp(e->d_name, "..") == 0)
				continue;
			(void)snprintf(p, sizeof(p), "%s/%s",
			    cfg_tmpdir_path, e->d_name);
			(void)unlink(p);
		}
		(void)closedir(d);
	}
	(void)rmdir(cfg_tmpdir_path);
	cfg_tmpdir_path[0] = '\0';
}

/* Lazily create (once per process) the temp dir and return its absolute path. */
static const char *
cfg_tmpdir(void)
{
	const char *base;
	char tmpl[PATH_MAX];

	if (cfg_tmpdir_path[0] != '\0')
		return (cfg_tmpdir_path);

	base = getenv("TMPDIR");
	if (base == NULL || base[0] == '\0')
		base = "/tmp";
	(void)snprintf(tmpl, sizeof(tmpl), "%s/blued-cfgtest.XXXXXX", base);
	ATF_REQUIRE_MSG(mkdtemp(tmpl) != NULL,
	    "mkdtemp(%s) failed: %s", tmpl, strerror(errno));
	strlcpy(cfg_tmpdir_path, tmpl, sizeof(cfg_tmpdir_path));
	ATF_REQUIRE(atexit(cfg_tmpdir_cleanup) == 0);
	return (cfg_tmpdir_path);
}

/* Build an absolute path for a named fixture inside the temp dir. */
static const char *
cfg_path(char *buf, size_t bufsz, const char *name)
{

	(void)snprintf(buf, bufsz, "%s/%s", cfg_tmpdir(), name);
	return (buf);
}

static void
write_config(const char *path, const char *text)
{
	FILE *fp;

	fp = fopen(path, "w");
	ATF_REQUIRE(fp != NULL);
	ATF_REQUIRE(fputs(text, fp) >= 0);
	ATF_REQUIRE(fclose(fp) == 0);
}

ATF_TC_WITHOUT_HEAD(defaults_for_missing_config);
ATF_TC_BODY(defaults_for_missing_config, tc)
{
	struct blued_config cfg;
	char pbuf[PATH_MAX];

	blued_config_defaults(&cfg);
	ATF_REQUIRE_EQ(blued_config_load(&cfg,
	    cfg_path(pbuf, sizeof(pbuf), "missing.conf")), 0);

	ATF_CHECK_STREQ(cfg.pidfile, "/var/run/blued.pid");
	ATF_CHECK_STREQ(cfg.bonddb, "/var/db/blued/bonds");
	ATF_CHECK_STREQ(cfg.ctlsock, "/var/run/blued.sock");
	ATF_CHECK_EQ(cfg.loglevel, 0);
	ATF_CHECK_EQ(cfg.nadapters, 0);
	ATF_CHECK_EQ(cfg.io_capability, SMP_IO_KEYBOARD_DISPLAY);
	ATF_CHECK(cfg.bondable);
	ATF_CHECK_EQ(cfg.sc_mode, BLUED_SC_ON);
	ATF_CHECK(cfg.eatt);
	ATF_CHECK(cfg.privacy);
	ATF_CHECK(cfg.reconnect);
	ATF_CHECK_EQ(cfg.reconnect_max_delay, 60);
}

ATF_TC_WITHOUT_HEAD(parses_nested_sample_shape);
ATF_TC_BODY(parses_nested_sample_shape, tc)
{
	struct blued_config cfg;
	char pbuf[PATH_MAX];
	const char *path = cfg_path(pbuf, sizeof(pbuf), "nested.conf");

	write_config(path,
	    "general {\n"
	    "  loglevel = 2;\n"
	    "  bonddb = \"/tmp/blued-bonds\";\n"
	    "  logfile = \"/tmp/blued.btsnoop\";\n"
	    "}\n"
	    "adapters = [\"ubt0\", \"ubt1\"];\n"
	    "security {\n"
	    "  io_capability = \"display_yesno\";\n"
	    "  bondable = false;\n"
	    "  sc = \"only\";\n"
	    "}\n"
	    "features {\n"
	    "  eatt = false;\n"
	    "  privacy = false;\n"
	    "  reconnect = false;\n"
	    "  reconnect_max_delay = 17;\n"
	    "}\n"
	    "devices {\n"
	    "  \"aa:bb:cc:dd:ee:ff\" {\n"
	    "    type = \"random\";\n"
	    "    reconnect = true;\n"
	    "  }\n"
	    "}\n");

	blued_config_defaults(&cfg);
	ATF_REQUIRE_EQ(blued_config_load(&cfg, path), 0);

	ATF_CHECK_EQ(cfg.loglevel, 2);
	ATF_CHECK_STREQ(cfg.bonddb, "/tmp/blued-bonds");
	ATF_CHECK_STREQ(cfg.logfile, "/tmp/blued.btsnoop");
	ATF_CHECK_EQ(cfg.nadapters, 2);
	ATF_CHECK_STREQ(cfg.adapters[0], "ubt0");
	ATF_CHECK_STREQ(cfg.adapters[1], "ubt1");
	ATF_CHECK_EQ(cfg.io_capability, SMP_IO_DISPLAY_YESNO);
	ATF_CHECK(!cfg.bondable);
	ATF_CHECK_EQ(cfg.sc_mode, BLUED_SC_ONLY);
	ATF_CHECK(!cfg.eatt);
	ATF_CHECK(!cfg.privacy);
	ATF_CHECK(!cfg.reconnect);
	ATF_CHECK_EQ(cfg.reconnect_max_delay, 17);
	ATF_CHECK_EQ(cfg.ndevices, 1);
	ATF_CHECK_EQ(cfg.devices[0].addr_type, BDADDR_LE_RANDOM);
	ATF_CHECK(cfg.devices[0].reconnect);
}

ATF_TC_WITHOUT_HEAD(parses_auto_adapter);
ATF_TC_BODY(parses_auto_adapter, tc)
{
	struct blued_config cfg;
	char pbuf[PATH_MAX];
	const char *path = cfg_path(pbuf, sizeof(pbuf), "auto-adapter.conf");

	write_config(path,
	    "adapters = [\"auto\"];\n");

	blued_config_defaults(&cfg);
	strlcpy(cfg.adapters[0], "ubt9", sizeof(cfg.adapters[0]));
	cfg.nadapters = 1;
	ATF_REQUIRE_EQ(blued_config_load(&cfg, path), 0);

	ATF_CHECK_EQ(cfg.nadapters, 0);
}

ATF_TC_WITHOUT_HEAD(ignores_top_level_legacy_shape);
ATF_TC_BODY(ignores_top_level_legacy_shape, tc)
{
	struct blued_config cfg;
	char pbuf[PATH_MAX];
	const char *path = cfg_path(pbuf, sizeof(pbuf), "legacy-top-level.conf");

	write_config(path,
	    "pidfile = \"/tmp/blued.pid\";\n"
	    "bonddb = \"/tmp/bonds\";\n"
	    "ctlsock = \"/tmp/blued.sock\";\n"
	    "logfile = \"/tmp/log\";\n"
	    "loglevel = 5;\n"
	    "daemonize = true;\n"
	    "eatt = false;\n"
	    "privacy = false;\n"
	    "reconnect = false;\n"
	    "reconnect_max_delay = 600;\n"
	    "devices = [{ addr = \"01:02:03:04:05:06\"; }];\n");

	blued_config_defaults(&cfg);
	ATF_REQUIRE_EQ(blued_config_load(&cfg, path), 0);

	ATF_CHECK_STREQ(cfg.pidfile, "/var/run/blued.pid");
	ATF_CHECK_STREQ(cfg.bonddb, "/var/db/blued/bonds");
	ATF_CHECK_STREQ(cfg.ctlsock, "/var/run/blued.sock");
	ATF_CHECK_STREQ(cfg.logfile, "");
	ATF_CHECK_EQ(cfg.loglevel, 0);
	ATF_CHECK(!cfg.daemonize);
	ATF_CHECK(cfg.eatt);
	ATF_CHECK(cfg.privacy);
	ATF_CHECK(cfg.reconnect);
	ATF_CHECK_EQ(cfg.reconnect_max_delay, 60);
	/*
	 * "devices" IS a top-level section, and the array form (bare device
	 * objects carrying "addr") is now parsed too, so this one is not a
	 * legacy shape: the device is recorded.
	 */
	ATF_CHECK_EQ(cfg.ndevices, 1);
}

ATF_TC_WITHOUT_HEAD(cli_overrides_config);
ATF_TC_BODY(cli_overrides_config, tc)
{
	struct blued_config cfg;
	char *argv[] = {
	    __DECONST(char *, "blued"),
	    __DECONST(char *, "-a"),
	    __DECONST(char *, "ubt9"),
	    __DECONST(char *, "-B"),
	    __DECONST(char *, "-f"),
	    __DECONST(char *, "/tmp/cli-bonds"),
	    __DECONST(char *, "-L"),
	    __DECONST(char *, "/tmp/cli-log"),
	    __DECONST(char *, "-p"),
	    __DECONST(char *, "-v"),
	    __DECONST(char *, "-v"),
	    NULL
	};

	blued_config_defaults(&cfg);
	blued_config_apply_cli(&cfg, nitems(argv) - 1, argv);

	ATF_CHECK_EQ(cfg.nadapters, 1);
	ATF_CHECK_STREQ(cfg.adapters[0], "ubt9");
	ATF_CHECK(cfg.daemonize);
	ATF_CHECK_STREQ(cfg.bonddb, "/tmp/cli-bonds");
	ATF_CHECK_STREQ(cfg.logfile, "/tmp/cli-log");
	ATF_CHECK(cfg.peripheral_mode);
	ATF_CHECK_EQ(cfg.loglevel, 2);
}

/*
 * Test: min_key_size parsing — default, valid, out of range
 */
ATF_TC_WITHOUT_HEAD(test_config_min_key_size);
ATF_TC_BODY(test_config_min_key_size, tc)
{
	struct blued_config cfg;
	char pbuf[PATH_MAX];
	const char *path = cfg_path(pbuf, sizeof(pbuf), "min_key_size.conf");

	/* Default should be 16 */
	blued_config_defaults(&cfg);
	ATF_CHECK_EQ(cfg.min_key_size, 16);

	/* Valid value within range [7, 16] */
	write_config(path,
	    "security {\n"
	    "  min_key_size = 10;\n"
	    "}\n");
	blued_config_defaults(&cfg);
	ATF_REQUIRE_EQ(blued_config_load(&cfg, path), 0);
	ATF_CHECK_EQ_MSG(cfg.min_key_size, 10,
	    "min_key_size should be 10, got %d", cfg.min_key_size);

	/* Below minimum — clamped to 7 */
	write_config(path,
	    "security {\n"
	    "  min_key_size = 3;\n"
	    "}\n");
	blued_config_defaults(&cfg);
	ATF_REQUIRE_EQ(blued_config_load(&cfg, path), 0);
	ATF_CHECK_EQ_MSG(cfg.min_key_size, 7,
	    "min_key_size 3 should be clamped to 7, got %d",
	    cfg.min_key_size);

	/* Above maximum — clamped to 16 */
	write_config(path,
	    "security {\n"
	    "  min_key_size = 99;\n"
	    "}\n");
	blued_config_defaults(&cfg);
	ATF_REQUIRE_EQ(blued_config_load(&cfg, path), 0);
	ATF_CHECK_EQ_MSG(cfg.min_key_size, 16,
	    "min_key_size 99 should be clamped to 16, got %d",
	    cfg.min_key_size);
}

/*
 * Test: 128-bit UUID service config parsing
 */
ATF_TC_WITHOUT_HEAD(test_config_service_uuid128);
ATF_TC_BODY(test_config_service_uuid128, tc)
{
	struct blued_config cfg;
	char pbuf[PATH_MAX];
	const char *path = cfg_path(pbuf, sizeof(pbuf), "svc128.conf");

	write_config(path,
	    "service {\n"
	    "  uuid = \"12345678-1234-5678-9abc-def012345678\";\n"
	    "}\n");
	blued_config_defaults(&cfg);
	ATF_REQUIRE_EQ(blued_config_load(&cfg, path), 0);
	ATF_CHECK_EQ(cfg.nservices, 1);
	ATF_CHECK_EQ(cfg.services[0].uuid16, 0);
}

ATF_TC_WITHOUT_HEAD(test_config_key_dist_exact_tokens);
ATF_TC_BODY(test_config_key_dist_exact_tokens, tc)
{
	struct blued_config cfg;
	char pbuf[PATH_MAX], text[512], value[257];
	const char *path = cfg_path(pbuf, sizeof(pbuf), "key-dist.conf");

	write_config(path,
	    "security { key_dist = \"enc + id, link, sign\"; }\n");
	blued_config_defaults(&cfg);
	ATF_REQUIRE_EQ(blued_config_load(&cfg, path), 0);
	ATF_CHECK_EQ(cfg.key_dist, SMP_KEY_DIST_ENC_KEY |
	    SMP_KEY_DIST_ID_KEY | SMP_KEY_DIST_LINK_KEY |
	    SMP_KEY_DIST_LEGACY_SIGN_KEY);

	write_config(path, "security { key_dist = \"encrypt_disabled,"
	    "identity,signature-off\"; }\n");
	blued_config_defaults(&cfg);
	ATF_REQUIRE_EQ(blued_config_load(&cfg, path), 0);
	ATF_CHECK_EQ(cfg.key_dist, 0);

	write_config(path, "security { key_dist = \" , +  enc, , id + \"; }\n");
	blued_config_defaults(&cfg);
	ATF_REQUIRE_EQ(blued_config_load(&cfg, path), 0);
	ATF_CHECK_EQ(cfg.key_dist, SMP_KEY_DIST_ENC_KEY | SMP_KEY_DIST_ID_KEY);

	memset(value, ' ', sizeof(value));
	memcpy(value, "enc", 3);
	value[255] = '\0';
	(void)snprintf(text, sizeof(text),
	    "security { key_dist = \"%s\"; }\n", value);
	write_config(path, text);
	blued_config_defaults(&cfg);
	ATF_REQUIRE_EQ(blued_config_load(&cfg, path), 0);
	ATF_CHECK_EQ(cfg.key_dist, SMP_KEY_DIST_ENC_KEY);

	value[255] = ' ';
	value[256] = '\0';
	(void)snprintf(text, sizeof(text),
	    "security { key_dist = \"%s\"; }\n", value);
	write_config(path, text);
	blued_config_defaults(&cfg);
	ATF_REQUIRE_EQ(blued_config_load(&cfg, path), 0);
	ATF_CHECK_EQ(cfg.key_dist, 0);
}

/*
 * Test: blued_parse_hex_value edge cases
 */
ATF_TC_WITHOUT_HEAD(test_config_hex_value_odd_length);
ATF_TC_BODY(test_config_hex_value_odd_length, tc)
{
	uint8_t buf[16];
	int ret;

	/* Even-length hex */
	ret = blued_parse_hex_value("0102", buf, sizeof(buf));
	ATF_CHECK_EQ(ret, 2);
	ATF_CHECK_EQ(buf[0], 0x01);
	ATF_CHECK_EQ(buf[1], 0x02);

	/*
	 * Odd-length hex is an ERROR: config.c blued_parse_hex_value returns
	 * -1 for "slen % 2 != 0".  "ret <= 0" also accepted 0 — the
	 * documented SUCCESS value for an empty value — so the assertion
	 * could not distinguish rejection from acceptance.
	 */
	ret = blued_parse_hex_value("012", buf, sizeof(buf));
	ATF_CHECK_EQ(ret, -1);

	/* Over-long input (slen / 2 > maxlen) is likewise -1. */
	ret = blued_parse_hex_value(
	    "000102030405060708090a0b0c0d0e0f10", buf, sizeof(buf));
	ATF_CHECK_EQ(ret, -1);

	/* Empty string: 0 bytes decoded, success. */
	ret = blued_parse_hex_value("", buf, sizeof(buf));
	ATF_CHECK_EQ(ret, 0);

	/*
	 * NULL string is folded into the empty-value case and returns 0
	 * (success, nothing decoded) — NOT an error.  The old comment/probe
	 * claimed failure while "ret <= 0" silently accepted the success
	 * path.
	 */
	ret = blued_parse_hex_value(NULL, buf, sizeof(buf));
	ATF_CHECK_EQ(ret, 0);
}

/* ================================================================
 * Test: malformed UCL (truncated, missing closing brace).
 * blued_config_load should return error or use defaults gracefully.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_config_malformed_ucl);
ATF_TC_BODY(test_config_malformed_ucl, tc)
{
	struct blued_config cfg;
	char pbuf[PATH_MAX];
	const char *path = cfg_path(pbuf, sizeof(pbuf), "malformed.conf");
	int ret;

	/* Truncated UCL — missing closing brace */
	write_config(path,
	    "general {\n"
	    "  loglevel = 3;\n"
	    "  bonddb = \"/tmp/bonds\";\n"
	    /* no closing brace */
	    );

	blued_config_defaults(&cfg);
	ret = blued_config_load(&cfg, path);

	/*
	 * Contract (config.c blued_config_load): a non-ENOENT parse failure
	 * returns -1 *before* config_parse_root() runs, so the caller's cfg is
	 * left exactly as blued_config_defaults() set it.  An unmatched open
	 * brace is a hard UCL syntax error, so the loader must reject it and
	 * must NOT partially apply the "loglevel = 3"/"bonddb" it did manage to
	 * lex.  Assert the mandated outcome, not merely "didn't crash".
	 */
	ATF_CHECK_EQ(ret, -1);
	ATF_CHECK_EQ(cfg.loglevel, 0);		/* default kept, not the 3 in-file */
	ATF_CHECK_STREQ(cfg.bonddb, "/var/db/blued/bonds");
	ATF_CHECK_STREQ(cfg.pidfile, "/var/run/blued.pid");
	ATF_CHECK_STREQ(cfg.ctlsock, "/var/run/blued.sock");
}

/* ================================================================
 * Test: blued_parse_gatt_properties — all valid tokens.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_parse_gatt_properties_all);
ATF_TC_BODY(test_parse_gatt_properties_all, tc)
{
	uint8_t props;

	props = blued_parse_gatt_properties(
	    "broadcast,read,write_no_rsp,write,notify,indicate,"
	    "auth_signed_write,extended");
	ATF_CHECK_EQ(props, 0xFF);

	/* Single property */
	ATF_CHECK_EQ(blued_parse_gatt_properties("read"), GATT_PROP_READ);
	ATF_CHECK_EQ(blued_parse_gatt_properties("notify"), GATT_PROP_NOTIFY);

	/* NULL and empty */
	ATF_CHECK_EQ(blued_parse_gatt_properties(NULL), 0);
	ATF_CHECK_EQ(blued_parse_gatt_properties(""), 0);

	/* Unknown token — should be silently ignored */
	ATF_CHECK_EQ(blued_parse_gatt_properties("bogus"), 0);
	ATF_CHECK_EQ(blued_parse_gatt_properties("read,bogus,write"),
	    GATT_PROP_READ | GATT_PROP_WRITE);
}

/* ================================================================
 * Test: blued_parse_gatt_properties — whitespace tolerance.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_parse_gatt_properties_whitespace);
ATF_TC_BODY(test_parse_gatt_properties_whitespace, tc)
{
	char boundary[261];

	ATF_CHECK_EQ(blued_parse_gatt_properties(" read , write "),
	    GATT_PROP_READ | GATT_PROP_WRITE);
	ATF_CHECK_EQ(blued_parse_gatt_properties(",,read,,notify,,"),
	    GATT_PROP_READ | GATT_PROP_NOTIFY);
	ATF_CHECK_EQ(blued_parse_gatt_properties("   ,\t, read ,   ,notify, "),
	    GATT_PROP_READ | GATT_PROP_NOTIFY);
	ATF_CHECK_EQ(blued_parse_gatt_properties("   ,\t,  "), 0);

	memset(boundary, ' ', sizeof(boundary));
	memcpy(boundary, "read", 4);
	boundary[254] = '\0';
	ATF_CHECK_EQ(blued_parse_gatt_properties(boundary), GATT_PROP_READ);
	boundary[254] = ' ';
	boundary[255] = '\0';
	ATF_CHECK_EQ(blued_parse_gatt_properties(boundary), GATT_PROP_READ);
	boundary[255] = ' ';
	boundary[256] = '\0';
	ATF_CHECK_EQ(blued_parse_gatt_properties(boundary), 0);
	memcpy(boundary + 256, "junk", 4);
	boundary[260] = '\0';
	ATF_CHECK_EQ(blued_parse_gatt_properties(boundary), 0);
}

/* ================================================================
 * Test: blued_parse_gatt_permissions — all valid tokens.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_parse_gatt_permissions_all);
ATF_TC_BODY(test_parse_gatt_permissions_all, tc)
{
	uint8_t perms;
	char boundary[261];

	perms = blued_parse_gatt_permissions(
	    "read,write,read_encrypt,write_encrypt,"
	    "read_authen,write_authen");
	ATF_CHECK_EQ(perms, 0x3F);

	/* Single */
	ATF_CHECK_EQ(blued_parse_gatt_permissions("read"), ATT_PERM_READ);
	ATF_CHECK_EQ(blued_parse_gatt_permissions("write_encrypt"),
	    ATT_PERM_WRITE_ENCRYPT);

	/* NULL and empty */
	ATF_CHECK_EQ(blued_parse_gatt_permissions(NULL), 0);
	ATF_CHECK_EQ(blued_parse_gatt_permissions(""), 0);
	ATF_CHECK_EQ(blued_parse_gatt_permissions(",,read,,write_authen,,"),
	    ATT_PERM_READ | ATT_PERM_WRITE_AUTHEN);
	ATF_CHECK_EQ(blued_parse_gatt_permissions(
	    "   ,\t, read_encrypt,   ,write, "),
	    ATT_PERM_READ_ENCRYPT | ATT_PERM_WRITE);
	ATF_CHECK_EQ(blued_parse_gatt_permissions("   ,\t,  "), 0);

	memset(boundary, ' ', sizeof(boundary));
	memcpy(boundary, "write", 5);
	boundary[254] = '\0';
	ATF_CHECK_EQ(blued_parse_gatt_permissions(boundary), ATT_PERM_WRITE);
	boundary[254] = ' ';
	boundary[255] = '\0';
	ATF_CHECK_EQ(blued_parse_gatt_permissions(boundary), ATT_PERM_WRITE);
	boundary[255] = ' ';
	boundary[256] = '\0';
	ATF_CHECK_EQ(blued_parse_gatt_permissions(boundary), 0);
	memcpy(boundary + 256, "junk", 4);
	boundary[260] = '\0';
	ATF_CHECK_EQ(blued_parse_gatt_permissions(boundary), 0);
}

/* ================================================================
 * Test: blued_parse_uuid — 16-bit UUID.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_parse_uuid_16bit);
ATF_TC_BODY(test_parse_uuid_16bit, tc)
{
	uint16_t uuid16;
	uint8_t uuid128[16];

	ATF_CHECK_EQ(blued_parse_uuid("0x1800", &uuid16, uuid128), 0);
	ATF_CHECK_EQ(uuid16, 0x1800);

	ATF_CHECK_EQ(blued_parse_uuid("0xFFFF", &uuid16, uuid128), 0);
	ATF_CHECK_EQ(uuid16, 0xFFFF);

	/* Invalid: 0x0000 */
	ATF_CHECK(blued_parse_uuid("0x0000", &uuid16, uuid128) != 0);

	/* Invalid: exceeds 16-bit range */
	ATF_CHECK(blued_parse_uuid("0x10000", &uuid16, uuid128) != 0);

	/* Invalid: trailing chars */
	ATF_CHECK(blued_parse_uuid("0x1800abc", &uuid16, uuid128) != 0);

	/* NULL */
	ATF_CHECK(blued_parse_uuid(NULL, &uuid16, uuid128) != 0);
}

/* ================================================================
 * Test: blued_parse_uuid — 128-bit UUID stored in little-endian.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_parse_uuid_128bit);
ATF_TC_BODY(test_parse_uuid_128bit, tc)
{
	uint16_t uuid16;
	uint8_t uuid128[16];

	ATF_CHECK_EQ(blued_parse_uuid(
	    "12345678-1234-5678-9abc-def012345678",
	    &uuid16, uuid128), 0);
	ATF_CHECK_EQ(uuid16, 0);

	/* Verify LE storage: big-endian display bytes reversed */
	ATF_CHECK_EQ(uuid128[15], 0x12);
	ATF_CHECK_EQ(uuid128[14], 0x34);
	ATF_CHECK_EQ(uuid128[0], 0x78);
}

/* ================================================================
 * Test: blued_parse_uuid — malformed 128-bit UUID.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_parse_uuid_128bit_malformed);
ATF_TC_BODY(test_parse_uuid_128bit_malformed, tc)
{
	uint16_t uuid16;
	uint8_t uuid128[16];

	/* Wrong length */
	ATF_CHECK(blued_parse_uuid(
	    "12345678-1234-5678-9abc-def01234567",
	    &uuid16, uuid128) != 0);

	/* No dashes */
	ATF_CHECK(blued_parse_uuid(
	    "12345678123456789abcdef012345678",
	    &uuid16, uuid128) != 0);

	/* Random text */
	ATF_CHECK(blued_parse_uuid("not-a-uuid", &uuid16, uuid128) != 0);
}

/* ================================================================
 * Test: blued_parse_hex_value — buffer overflow protection.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_parse_hex_value_overflow);
ATF_TC_BODY(test_parse_hex_value_overflow, tc)
{
	uint8_t buf[4];

	/* Hex produces 5 bytes but buf is only 4 — should fail */
	ATF_CHECK(blued_parse_hex_value("0102030405", buf, sizeof(buf)) < 0);

	/* Exactly fits */
	ATF_CHECK_EQ(blued_parse_hex_value("01020304", buf, sizeof(buf)), 4);
}

/* ================================================================
 * Test: blued_parse_hex_value — invalid hex chars.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_parse_hex_value_invalid_chars);
ATF_TC_BODY(test_parse_hex_value_invalid_chars, tc)
{
	uint8_t buf[16];

	ATF_CHECK(blued_parse_hex_value("GGGG", buf, sizeof(buf)) < 0);
	ATF_CHECK(blued_parse_hex_value("zz", buf, sizeof(buf)) < 0);
}

/* ================================================================
 * Test: config feature parsing — rpa_timeout clamping.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_config_rpa_timeout);
ATF_TC_BODY(test_config_rpa_timeout, tc)
{
	struct blued_config cfg;
	char pbuf[PATH_MAX];
	const char *path = cfg_path(pbuf, sizeof(pbuf), "rpa_timeout.conf");

	/* Default = 900 */
	blued_config_defaults(&cfg);
	ATF_CHECK_EQ(cfg.rpa_timeout, 900);

	/* Valid value */
	write_config(path,
	    "features {\n"
	    "  rpa_timeout = 300;\n"
	    "}\n");
	blued_config_defaults(&cfg);
	ATF_REQUIRE_EQ(blued_config_load(&cfg, path), 0);
	ATF_CHECK_EQ(cfg.rpa_timeout, 300);

	/* Below minimum — clamped to 1 */
	write_config(path,
	    "features {\n"
	    "  rpa_timeout = 0;\n"
	    "}\n");
	blued_config_defaults(&cfg);
	ATF_REQUIRE_EQ(blued_config_load(&cfg, path), 0);
	ATF_CHECK_EQ(cfg.rpa_timeout, 1);

	/* Above maximum — clamped to 3600 */
	write_config(path,
	    "features {\n"
	    "  rpa_timeout = 99999;\n"
	    "}\n");
	blued_config_defaults(&cfg);
	ATF_REQUIRE_EQ(blued_config_load(&cfg, path), 0);
	ATF_CHECK_EQ(cfg.rpa_timeout, 3600);
}

/* ================================================================
 * Test: config feature parsing — subrate_factor clamping.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_config_subrate_factor);
ATF_TC_BODY(test_config_subrate_factor, tc)
{
	struct blued_config cfg;
	char pbuf[PATH_MAX];
	const char *path = cfg_path(pbuf, sizeof(pbuf), "subrate.conf");

	/*
	 * subrate_factor is reserved for BT 5.3 and is no longer parsed.
	 * Verify it stays at its default (0) even when the config file
	 * contains a value.
	 */
	blued_config_defaults(&cfg);
	ATF_CHECK_EQ(cfg.subrate_factor, 0);

	write_config(path,
	    "features {\n"
	    "  subrate_factor = 250;\n"
	    "}\n");
	blued_config_defaults(&cfg);
	ATF_REQUIRE_EQ(blued_config_load(&cfg, path), 0);
	ATF_CHECK_EQ(cfg.subrate_factor, 0);	/* not parsed — stays 0 */

	write_config(path,
	    "features {\n"
	    "  subrate_factor = 9999;\n"
	    "}\n");
	blued_config_defaults(&cfg);
	ATF_REQUIRE_EQ(blued_config_load(&cfg, path), 0);
	ATF_CHECK_EQ(cfg.subrate_factor, 0);	/* not parsed — stays 0 */
}

/* ================================================================
 * Test: config — privacy_mode parsing.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_config_privacy_mode);
ATF_TC_BODY(test_config_privacy_mode, tc)
{
	struct blued_config cfg;
	char pbuf[PATH_MAX];
	const char *path = cfg_path(pbuf, sizeof(pbuf), "privacy_mode.conf");

	/* Default is device (1) */
	blued_config_defaults(&cfg);
	ATF_CHECK_EQ(cfg.privacy_mode, 1);

	write_config(path,
	    "features {\n"
	    "  privacy_mode = \"network\";\n"
	    "}\n");
	blued_config_defaults(&cfg);
	ATF_REQUIRE_EQ(blued_config_load(&cfg, path), 0);
	ATF_CHECK_EQ(cfg.privacy_mode, 0);

	write_config(path,
	    "features {\n"
	    "  privacy_mode = \"device\";\n"
	    "}\n");
	blued_config_defaults(&cfg);
	ATF_REQUIRE_EQ(blued_config_load(&cfg, path), 0);
	ATF_CHECK_EQ(cfg.privacy_mode, 1);
}

/* ================================================================
 * Test: config — io_capability parsing with all valid strings.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_config_io_capability_all);
ATF_TC_BODY(test_config_io_capability_all, tc)
{
	struct blued_config cfg;
	char pbuf[PATH_MAX];
	const char *path = cfg_path(pbuf, sizeof(pbuf), "io_cap.conf");
	struct {
		const char *name;
		uint8_t expected;
	} cases[] = {
		{ "display_only",       SMP_IO_DISPLAY_ONLY },
		{ "display_yesno",      SMP_IO_DISPLAY_YESNO },
		{ "keyboard_only",      SMP_IO_KEYBOARD_ONLY },
		{ "no_input_no_output", SMP_IO_NO_INPUT_NO_OUTPUT },
		{ "none",               SMP_IO_NO_INPUT_NO_OUTPUT },
		{ "keyboard_display",   SMP_IO_KEYBOARD_DISPLAY },
	};

	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		char buf[256];
		snprintf(buf, sizeof(buf),
		    "security {\n"
		    "  io_capability = \"%s\";\n"
		    "}\n", cases[i].name);
		write_config(path, buf);
		blued_config_defaults(&cfg);
		ATF_REQUIRE_EQ(blued_config_load(&cfg, path), 0);
		ATF_CHECK_EQ_MSG(cfg.io_capability, cases[i].expected,
		    "io_capability '%s': expected %d, got %d",
		    cases[i].name, cases[i].expected, cfg.io_capability);
	}
}

/*
 * SR1: min_pairing_security parses each policy level, defaults to the secure
 * "auth" floor, and falls back to "auth" for an unknown value.
 */
ATF_TC_WITHOUT_HEAD(test_config_min_pairing_security);
ATF_TC_BODY(test_config_min_pairing_security, tc)
{
	struct blued_config cfg;
	char pbuf[PATH_MAX];
	const char *path = cfg_path(pbuf, sizeof(pbuf), "minsec.conf");
	struct {
		const char *name;
		uint8_t expected;
	} cases[] = {
		{ "none", SMP_SEC_NONE },
		{ "enc",  SMP_SEC_ENC },
		{ "auth", SMP_SEC_AUTH },
		{ "sc",   SMP_SEC_SC },
		{ "bogus", SMP_SEC_AUTH },	/* unknown -> secure default */
	};

	/* Default (no key present) must be the secure authenticated floor. */
	blued_config_defaults(&cfg);
	ATF_CHECK_EQ_MSG(cfg.min_pairing_security, SMP_SEC_AUTH,
	    "default min_pairing_security must be auth (%d), got %d",
	    SMP_SEC_AUTH, cfg.min_pairing_security);

	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		char buf[256];
		snprintf(buf, sizeof(buf),
		    "security {\n"
		    "  min_pairing_security = \"%s\";\n"
		    "}\n", cases[i].name);
		write_config(path, buf);
		blued_config_defaults(&cfg);
		ATF_REQUIRE_EQ(blued_config_load(&cfg, path), 0);
		ATF_CHECK_EQ_MSG(cfg.min_pairing_security, cases[i].expected,
		    "min_pairing_security '%s': expected %d, got %d",
		    cases[i].name, cases[i].expected,
		    cfg.min_pairing_security);
	}
}

/* ================================================================
 * Test: config — service with characteristic including notify/CCCD.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_config_service_with_char);
ATF_TC_BODY(test_config_service_with_char, tc)
{
	struct blued_config cfg;
	char pbuf[PATH_MAX];
	const char *path = cfg_path(pbuf, sizeof(pbuf), "svc_char.conf");

	write_config(path,
	    "service {\n"
	    "  uuid = \"0xFFE0\";\n"
	    "  characteristic {\n"
	    "    uuid = \"0xFFE1\";\n"
	    "    properties = \"read,notify\";\n"
	    "    permissions = \"read\";\n"
	    "    value = \"0100\";\n"
	    "  }\n"
	    "}\n");

	blued_config_defaults(&cfg);
	ATF_REQUIRE_EQ(blued_config_load(&cfg, path), 0);
	ATF_CHECK_EQ(cfg.nservices, 1);
	ATF_CHECK_EQ(cfg.services[0].uuid16, 0xFFE0);
	ATF_CHECK_EQ(cfg.services[0].nchars, 1);
	ATF_CHECK_EQ(cfg.services[0].chars[0].uuid16, 0xFFE1);
	ATF_CHECK_EQ(cfg.services[0].chars[0].properties,
	    GATT_PROP_READ | GATT_PROP_NOTIFY);
	ATF_CHECK_EQ(cfg.services[0].chars[0].permissions, ATT_PERM_READ);
	ATF_CHECK(cfg.services[0].chars[0].has_cccd);
	ATF_CHECK_EQ(cfg.services[0].chars[0].initial_value_len, 2);
	ATF_CHECK_EQ(cfg.services[0].chars[0].initial_value[0], 0x01);
	ATF_CHECK_EQ(cfg.services[0].chars[0].initial_value[1], 0x00);
}

/* ================================================================
 * Test: config — reconnect_max_delay clamping.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_config_reconnect_max_delay_clamp);
ATF_TC_BODY(test_config_reconnect_max_delay_clamp, tc)
{
	struct blued_config cfg;
	char pbuf[PATH_MAX];
	const char *path = cfg_path(pbuf, sizeof(pbuf), "rcdelay.conf");

	/* Below minimum — clamped to 1 */
	write_config(path,
	    "features {\n"
	    "  reconnect_max_delay = 0;\n"
	    "}\n");
	blued_config_defaults(&cfg);
	ATF_REQUIRE_EQ(blued_config_load(&cfg, path), 0);
	ATF_CHECK_EQ(cfg.reconnect_max_delay, 1);

	/* Above maximum — clamped to 3600 */
	write_config(path,
	    "features {\n"
	    "  reconnect_max_delay = 99999;\n"
	    "}\n");
	blued_config_defaults(&cfg);
	ATF_REQUIRE_EQ(blued_config_load(&cfg, path), 0);
	ATF_CHECK_EQ(cfg.reconnect_max_delay, 3600);
}

/* ================================================================
 * The default key-distribution mask is the FULL set 0x0f =
 * ENC|ID|SIGN|LINK.
 *
 * This test previously pinned 0x0b (ENC|ID|LINK, "must NOT include
 * CSRK/sign") -- which is precisely what made the CSRK distribution and
 * restore paths dead code: every smp_conn producer in the daemon
 * (blued_central.c, both blued_peripheral.c paths) overwrites the library
 * seed from smp_seed_policy_defaults() with cfg.key_dist, so the narrower
 * config default silently won on the wire and SignKey never appeared in a
 * Pairing Request/Response.  The two defaults are now pinned to each other
 * by a _Static_assert in config.c; this test guards the value itself and
 * the SIGN bit specifically.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_config_key_dist_default_is_enc_id_link);
ATF_TC_BODY(test_config_key_dist_default_is_enc_id_link, tc)
{
	struct blued_config cfg;

	ATF_CHECK_EQ_MSG(SMP_KEY_DIST_ENC_KEY | SMP_KEY_DIST_ID_KEY |
	    SMP_KEY_DIST_LEGACY_SIGN_KEY | SMP_KEY_DIST_LINK_KEY,
	    BLUED_KEY_DIST_DEFAULT,
	    "default mask must be ENC|ID|SIGN|LINK (0x0f)");
	ATF_CHECK_EQ_MSG(0x0f, BLUED_KEY_DIST_DEFAULT,
	    "default mask must be 0x0f");
	ATF_CHECK_MSG((BLUED_KEY_DIST_DEFAULT & SMP_KEY_DIST_LEGACY_SIGN_KEY)
	    != 0, "default mask must include CSRK/sign or signed writes are "
	    "unreachable");
	/* The config default must not narrow the SMP library's own seed. */
	ATF_CHECK_EQ_MSG(SMP_KEY_DIST_DEFAULT, BLUED_KEY_DIST_DEFAULT,
	    "config default must match smp_seed_policy_defaults()");

	blued_config_defaults(&cfg);
	ATF_CHECK_EQ(cfg.key_dist, BLUED_KEY_DIST_DEFAULT);
}

/*
 * The operator must be able to express the default set, including SignKey:
 * the parser's token table has to carry "sign" or the config cannot round-trip
 * its own default.
 */
ATF_TC_WITHOUT_HEAD(test_config_key_dist_sign_token_round_trip);
ATF_TC_BODY(test_config_key_dist_sign_token_round_trip, tc)
{
	struct blued_config cfg;
	char pbuf[PATH_MAX];
	const char *path = cfg_path(pbuf, sizeof(pbuf), "key-dist-sign.conf");

	write_config(path, "security { key_dist = \"enc,id,sign,link\"; }\n");
	blued_config_defaults(&cfg);
	ATF_REQUIRE_EQ(blued_config_load(&cfg, path), 0);
	ATF_CHECK_EQ_MSG(BLUED_KEY_DIST_DEFAULT, cfg.key_dist,
	    "\"enc,id,sign,link\" must reproduce the default mask");

	/* "sign" alone must set exactly the CSRK bit. */
	write_config(path, "security { key_dist = \"sign\"; }\n");
	blued_config_defaults(&cfg);
	ATF_REQUIRE_EQ(blued_config_load(&cfg, path), 0);
	ATF_CHECK_EQ(cfg.key_dist, SMP_KEY_DIST_LEGACY_SIGN_KEY);

	/* Dropping "sign" must be expressible too. */
	write_config(path, "security { key_dist = \"enc,id,link\"; }\n");
	blued_config_defaults(&cfg);
	ATF_REQUIRE_EQ(blued_config_load(&cfg, path), 0);
	ATF_CHECK_EQ(cfg.key_dist, SMP_KEY_DIST_ENC_KEY |
	    SMP_KEY_DIST_ID_KEY | SMP_KEY_DIST_LINK_KEY);
}

/* ================================================================
 * Finding 97: auto_connect_max_tries was a silent no-op knob and has
 * been removed.  A config that still specifies it must load cleanly
 * (the unknown key is ignored), with auto_connect unaffected.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_config_auto_connect_max_tries_removed);
ATF_TC_BODY(test_config_auto_connect_max_tries_removed, tc)
{
	struct blued_config cfg;
	char pbuf[PATH_MAX];
	const char *path = cfg_path(pbuf, sizeof(pbuf), "actries.conf");

	write_config(path,
	    "features {\n"
	    "  auto_connect = true;\n"
	    "  auto_connect_max_tries = 1;\n"
	    "}\n");
	blued_config_defaults(&cfg);
	ATF_REQUIRE_EQ(blued_config_load(&cfg, path), 0);
	ATF_CHECK(cfg.auto_connect);
}

/* ================================================================
 * Finding 136: descriptor { } and include { } sub-blocks are parsed
 * into the service/characteristic config so operators can author
 * non-CCCD descriptors and included services without a program.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_config_descriptor_and_include);
ATF_TC_BODY(test_config_descriptor_and_include, tc)
{
	struct blued_config cfg;
	char pbuf[PATH_MAX];
	const char *path = cfg_path(pbuf, sizeof(pbuf), "desc_inc.conf");
	const struct blued_char_conf *ch;
	const struct blued_service_conf *svc;

	write_config(path,
	    "service {\n"
	    "  uuid = \"0x180F\";\n"
	    "  include {\n"
	    "    start = 16;\n"
	    "    end = 32;\n"
	    "    uuid = \"0x1801\";\n"
	    "  }\n"
	    "  characteristic {\n"
	    "    uuid = \"0x2A19\";\n"
	    "    properties = \"read,notify\";\n"
	    "    permissions = \"read\";\n"
	    "    value = \"64\";\n"
	    "    descriptor {\n"
	    "      uuid = \"0x2901\";\n"
	    "      permissions = \"read\";\n"
	    "      value = \"4C6576656C\";\n"
	    "    }\n"
	    "  }\n"
	    "}\n");

	blued_config_defaults(&cfg);
	ATF_REQUIRE_EQ(blued_config_load(&cfg, path), 0);
	ATF_REQUIRE_EQ(cfg.nservices, 1);
	svc = &cfg.services[0];
	ATF_CHECK_EQ(svc->uuid16, 0x180F);

	/* Included service parsed. */
	ATF_REQUIRE_EQ(svc->nincludes, 1);
	ATF_CHECK_EQ(svc->includes[0].start, 16);
	ATF_CHECK_EQ(svc->includes[0].end, 32);
	ATF_CHECK_EQ(svc->includes[0].uuid16, 0x1801);

	/* Characteristic + descriptor parsed. */
	ATF_REQUIRE_EQ(svc->nchars, 1);
	ch = &svc->chars[0];
	ATF_CHECK_EQ(ch->uuid16, 0x2A19);
	ATF_REQUIRE_EQ(ch->ndescs, 1);
	ATF_CHECK_EQ(ch->descs[0].uuid16, 0x2901);
	ATF_CHECK_EQ(ch->descs[0].permissions, ATT_PERM_READ);
	ATF_REQUIRE_EQ(ch->descs[0].value_len, 5);
	ATF_CHECK_EQ(ch->descs[0].value[0], 0x4C);
	ATF_CHECK_EQ(ch->descs[0].value[4], 0x6C);
}

/* An include with an inverted/zero handle range is rejected (not stored). */
ATF_TC_WITHOUT_HEAD(test_config_include_bad_range);
ATF_TC_BODY(test_config_include_bad_range, tc)
{
	struct blued_config cfg;
	char pbuf[PATH_MAX];
	const char *path = cfg_path(pbuf, sizeof(pbuf), "inc_bad.conf");

	write_config(path,
	    "service {\n"
	    "  uuid = \"0x180A\";\n"
	    "  include {\n"
	    "    start = 40;\n"
	    "    end = 20;\n"
	    "  }\n"
	    "}\n");

	blued_config_defaults(&cfg);
	ATF_REQUIRE_EQ(blued_config_load(&cfg, path), 0);
	ATF_REQUIRE_EQ(cfg.nservices, 1);
	ATF_CHECK_EQ(cfg.services[0].nincludes, 0);
}

/* ================================================================
 * Compatibility profile (config `compatibility_profile`, blued(8) -P)
 *
 * These cases exercise the PARSER and the command line.  That a profile
 * actually reaches the wire is asserted elsewhere, on real PDU octets:
 * gatt_hash_order_test for the Database Hash order, att_server_edge_test for
 * the ATT error selection.
 * ================================================================ */

/* Every canonical token and every synonym resolves the whole family. */
ATF_TC_WITHOUT_HEAD(compat_profile_tokens);
ATF_TC_BODY(compat_profile_tokens, tc)
{
	static const struct {
		const char	*token;
		uint8_t		 profile;
		uint8_t		 hash_order;
		uint8_t		 errsel;
	} cases[] = {
	    { "default",	BLUED_COMPAT_DEFAULT,
	      BLUED_DB_HASH_ORDER_BLUEZ,	BLUED_ATT_ERRSEL_SPEC },
	    { "spec",		BLUED_COMPAT_SPEC,
	      BLUED_DB_HASH_ORDER_REVERSED,	BLUED_ATT_ERRSEL_SPEC },
	    { "strict",		BLUED_COMPAT_SPEC,
	      BLUED_DB_HASH_ORDER_REVERSED,	BLUED_ATT_ERRSEL_SPEC },
	    { "qualification",	BLUED_COMPAT_SPEC,
	      BLUED_DB_HASH_ORDER_REVERSED,	BLUED_ATT_ERRSEL_SPEC },
	    { "PTS",		BLUED_COMPAT_SPEC,
	      BLUED_DB_HASH_ORDER_REVERSED,	BLUED_ATT_ERRSEL_SPEC },
	    { "bluez",		BLUED_COMPAT_BLUEZ,
	      BLUED_DB_HASH_ORDER_BLUEZ,	BLUED_ATT_ERRSEL_BLUEZ },
	    { "Linux",		BLUED_COMPAT_BLUEZ,
	      BLUED_DB_HASH_ORDER_BLUEZ,	BLUED_ATT_ERRSEL_BLUEZ },
	};
	struct blued_config cfg;
	char pbuf[PATH_MAX], text[128];
	const char *path = cfg_path(pbuf, sizeof(pbuf), "profile.conf");
	size_t i;

	for (i = 0; i < nitems(cases); i++) {
		(void)snprintf(text, sizeof(text),
		    "compatibility_profile = \"%s\";\n", cases[i].token);
		blued_config_defaults(&cfg);
		write_config(path, text);
		ATF_REQUIRE_EQ(0, blued_config_load(&cfg, path));
		ATF_CHECK_EQ_MSG(cases[i].profile, cfg.compat_profile,
		    "token '%s' selected the wrong profile", cases[i].token);
		ATF_CHECK_EQ_MSG(cases[i].hash_order, cfg.db_hash_byte_order,
		    "profile '%s' resolved the wrong Database Hash order",
		    cases[i].token);
		ATF_CHECK_EQ_MSG(cases[i].errsel, cfg.att_error_selection,
		    "profile '%s' resolved the wrong ATT error selection",
		    cases[i].token);
		ATF_CHECK_EQ_MSG(0u, cfg.compat_overrides,
		    "profile '%s' must not mark any knob individually set",
		    cases[i].token);
	}

	/* The short spelling names the same key. */
	blued_config_defaults(&cfg);
	write_config(path, "compat_profile = \"bluez\";\n");
	ATF_REQUIRE_EQ(0, blued_config_load(&cfg, path));
	ATF_CHECK_EQ(BLUED_COMPAT_BLUEZ, cfg.compat_profile);
	ATF_CHECK_EQ(BLUED_ATT_ERRSEL_BLUEZ, cfg.att_error_selection);
}

/*
 * The shipped default is a real profile whose column equals the shipped
 * defaults, so a configuration that names nothing comes out unchanged.  This
 * is the "upgrading changes nothing silently" promise, asserted rather than
 * asserted-in-a-comment.
 */
ATF_TC_WITHOUT_HEAD(compat_profile_default_preserves_shipped_behaviour);
ATF_TC_BODY(compat_profile_default_preserves_shipped_behaviour, tc)
{
	struct blued_config cfg, shipped;
	char pbuf[PATH_MAX];
	const char *path = cfg_path(pbuf, sizeof(pbuf), "empty.conf");

	blued_config_defaults(&shipped);
	ATF_CHECK_EQ(BLUED_COMPAT_DEFAULT, shipped.compat_profile);
	ATF_CHECK_EQ(BLUED_DB_HASH_ORDER_BLUEZ, shipped.db_hash_byte_order);
	ATF_CHECK_EQ(BLUED_ATT_ERRSEL_SPEC, shipped.att_error_selection);

	/* A file that mentions something else must not disturb the family. */
	blued_config_defaults(&cfg);
	write_config(path, "general { loglevel = 2; }\n");
	ATF_REQUIRE_EQ(0, blued_config_load(&cfg, path));
	ATF_CHECK_EQ(shipped.db_hash_byte_order, cfg.db_hash_byte_order);
	ATF_CHECK_EQ(shipped.att_error_selection, cfg.att_error_selection);

	/* Nor must an explicit "default". */
	blued_config_defaults(&cfg);
	write_config(path, "compatibility_profile = \"default\";\n");
	ATF_REQUIRE_EQ(0, blued_config_load(&cfg, path));
	ATF_CHECK_EQ(shipped.db_hash_byte_order, cfg.db_hash_byte_order);
	ATF_CHECK_EQ(shipped.att_error_selection, cfg.att_error_selection);
}

/* An unparsable profile is refused, not silently substituted. */
ATF_TC_WITHOUT_HEAD(compat_profile_rejects_invalid_value);
ATF_TC_BODY(compat_profile_rejects_invalid_value, tc)
{
	struct blued_config cfg;
	char pbuf[PATH_MAX];
	const char *path = cfg_path(pbuf, sizeof(pbuf), "badprofile.conf");

	blued_config_defaults(&cfg);
	write_config(path, "compatibility_profile = \"zephyr\";\n");
	ATF_REQUIRE_EQ(0, blued_config_load(&cfg, path));
	ATF_CHECK_EQ_MSG(BLUED_COMPAT_DEFAULT, cfg.compat_profile,
	    "an unknown profile must leave the previous one in force");
	ATF_CHECK_EQ(BLUED_DB_HASH_ORDER_BLUEZ, cfg.db_hash_byte_order);
	ATF_CHECK_EQ(BLUED_ATT_ERRSEL_SPEC, cfg.att_error_selection);

	/* A rejected value must not undo a profile already in force. */
	blued_config_defaults(&cfg);
	write_config(path,
	    "compatibility_profile = \"bluez\";\n"
	    "compat_profile = \"nonsense\";\n");
	ATF_REQUIRE_EQ(0, blued_config_load(&cfg, path));
	ATF_CHECK_EQ(BLUED_COMPAT_BLUEZ, cfg.compat_profile);
	ATF_CHECK_EQ(BLUED_ATT_ERRSEL_BLUEZ, cfg.att_error_selection);

	/* A non-string value is ignored outright. */
	blued_config_defaults(&cfg);
	write_config(path, "compatibility_profile = 3;\n");
	ATF_REQUIRE_EQ(0, blued_config_load(&cfg, path));
	ATF_CHECK_EQ(BLUED_COMPAT_DEFAULT, cfg.compat_profile);
}

/* An individually named knob beats the profile, and says so. */
ATF_TC_WITHOUT_HEAD(compat_knob_overrides_profile);
ATF_TC_BODY(compat_knob_overrides_profile, tc)
{
	struct blued_config cfg;
	char pbuf[PATH_MAX];
	const char *path = cfg_path(pbuf, sizeof(pbuf), "override.conf");

	/* spec, but keep BlueZ's hash order for already-deployed peers. */
	blued_config_defaults(&cfg);
	write_config(path,
	    "compatibility_profile = \"spec\";\n"
	    "gatt { database_hash_byte_order = \"bluez\"; }\n");
	ATF_REQUIRE_EQ(0, blued_config_load(&cfg, path));
	ATF_CHECK_EQ(BLUED_COMPAT_SPEC, cfg.compat_profile);
	ATF_CHECK_EQ_MSG(BLUED_DB_HASH_ORDER_BLUEZ, cfg.db_hash_byte_order,
	    "the named knob must beat the profile");
	ATF_CHECK_EQ_MSG(BLUED_ATT_ERRSEL_SPEC, cfg.att_error_selection,
	    "the rest of the family must still come from the profile");
	ATF_CHECK((cfg.compat_overrides & BLUED_COMPAT_OVR_DB_HASH_ORDER) != 0);
	ATF_CHECK_EQ(0u, cfg.compat_overrides & BLUED_COMPAT_OVR_ATT_ERRSEL);

	/* bluez, but answer denied requests by the specification. */
	blued_config_defaults(&cfg);
	write_config(path,
	    "compatibility_profile = \"bluez\";\n"
	    "gatt { att_error_selection = \"spec\"; }\n");
	ATF_REQUIRE_EQ(0, blued_config_load(&cfg, path));
	ATF_CHECK_EQ(BLUED_ATT_ERRSEL_SPEC, cfg.att_error_selection);
	ATF_CHECK_EQ(BLUED_DB_HASH_ORDER_BLUEZ, cfg.db_hash_byte_order);
	ATF_CHECK((cfg.compat_overrides & BLUED_COMPAT_OVR_ATT_ERRSEL) != 0);

	/*
	 * Key order in the file must not matter: the profile is folded in
	 * after the whole file is parsed, not as it is encountered.
	 */
	blued_config_defaults(&cfg);
	write_config(path,
	    "gatt { att_error_selection = \"spec\"; }\n"
	    "compatibility_profile = \"bluez\";\n");
	ATF_REQUIRE_EQ(0, blued_config_load(&cfg, path));
	ATF_CHECK_EQ_MSG(BLUED_ATT_ERRSEL_SPEC, cfg.att_error_selection,
	    "a knob named before the profile must still win");
}

/* The att_error_selection tokens, and its refusal of a bad value. */
ATF_TC_WITHOUT_HEAD(att_error_selection_tokens);
ATF_TC_BODY(att_error_selection_tokens, tc)
{
	static const struct {
		const char	*token;
		uint8_t		 sel;
	} cases[] = {
	    { "spec",		BLUED_ATT_ERRSEL_SPEC },
	    { "table_10_2",	BLUED_ATT_ERRSEL_SPEC },
	    { "table-10-2",	BLUED_ATT_ERRSEL_SPEC },
	    { "key_state",	BLUED_ATT_ERRSEL_SPEC },
	    { "key-state",	BLUED_ATT_ERRSEL_SPEC },
	    { "zephyr",		BLUED_ATT_ERRSEL_SPEC },
	    { "nimble",		BLUED_ATT_ERRSEL_SPEC },
	    { "bluez",		BLUED_ATT_ERRSEL_BLUEZ },
	    { "linux",		BLUED_ATT_ERRSEL_BLUEZ },
	    { "permissions",	BLUED_ATT_ERRSEL_BLUEZ },
	    { "permission_bits", BLUED_ATT_ERRSEL_BLUEZ },
	    { "permission-bits", BLUED_ATT_ERRSEL_BLUEZ },
	};
	struct blued_config cfg;
	char pbuf[PATH_MAX], text[160];
	const char *path = cfg_path(pbuf, sizeof(pbuf), "errsel.conf");
	size_t i;

	for (i = 0; i < nitems(cases); i++) {
		(void)snprintf(text, sizeof(text),
		    "gatt { att_error_selection = \"%s\"; }\n",
		    cases[i].token);
		blued_config_defaults(&cfg);
		write_config(path, text);
		ATF_REQUIRE_EQ(0, blued_config_load(&cfg, path));
		ATF_CHECK_EQ_MSG(cases[i].sel, cfg.att_error_selection,
		    "token '%s' selected the wrong ATT error selection",
		    cases[i].token);
		ATF_CHECK((cfg.compat_overrides &
		    BLUED_COMPAT_OVR_ATT_ERRSEL) != 0);
	}

	/* Unknown: keep what was in force, and do not claim an override. */
	blued_config_defaults(&cfg);
	write_config(path,
	    "gatt { att_error_selection = \"permission_bit\"; }\n");
	ATF_REQUIRE_EQ(0, blued_config_load(&cfg, path));
	ATF_CHECK_EQ(BLUED_ATT_ERRSEL_SPEC, cfg.att_error_selection);
	ATF_CHECK_EQ_MSG(0u,
	    cfg.compat_overrides & BLUED_COMPAT_OVR_ATT_ERRSEL,
	    "a rejected value must not pin the knob against the profile");

	/*
	 * And because it did not pin the knob, a profile named in the same
	 * file still governs it.
	 */
	blued_config_defaults(&cfg);
	write_config(path,
	    "compatibility_profile = \"bluez\";\n"
	    "gatt { att_error_selection = \"permission_bit\"; }\n");
	ATF_REQUIRE_EQ(0, blued_config_load(&cfg, path));
	ATF_CHECK_EQ(BLUED_ATT_ERRSEL_BLUEZ, cfg.att_error_selection);
}

/* -P: every spelling, an invalid value, and no argument-swallowing. */
ATF_TC_WITHOUT_HEAD(compat_profile_cli_option);
ATF_TC_BODY(compat_profile_cli_option, tc)
{
	char *argv[] = { __DECONST(char *, "blued"),
	    __DECONST(char *, "-P"), __DECONST(char *, "spec"),
	    __DECONST(char *, "-p"), NULL };
	char *argv_bluez[] = { __DECONST(char *, "blued"),
	    __DECONST(char *, "-P"), __DECONST(char *, "linux"), NULL };
	char *argv_bad[] = { __DECONST(char *, "blued"),
	    __DECONST(char *, "-P"), __DECONST(char *, "spectacular"), NULL };
	struct blued_config cfg;

	ATF_CHECK_MSG(strstr(BLUED_GETOPT_STRING, "P:") != NULL,
	    "-P must be declared as taking an argument in the shared option "
	    "string used by both getopt passes");

	blued_config_defaults(&cfg);
	blued_config_apply_cli(&cfg, 4, argv);
	ATF_CHECK_EQ(BLUED_COMPAT_SPEC, cfg.compat_profile);
	ATF_CHECK_EQ(BLUED_DB_HASH_ORDER_REVERSED, cfg.db_hash_byte_order);
	ATF_CHECK_EQ(BLUED_ATT_ERRSEL_SPEC, cfg.att_error_selection);
	ATF_CHECK_MSG(cfg.peripheral_mode,
	    "-P's argument must not swallow the following option");

	blued_config_defaults(&cfg);
	blued_config_apply_cli(&cfg, 3, argv_bluez);
	ATF_CHECK_EQ(BLUED_COMPAT_BLUEZ, cfg.compat_profile);
	ATF_CHECK_EQ(BLUED_ATT_ERRSEL_BLUEZ, cfg.att_error_selection);

	/* Invalid: the profile already in force survives untouched. */
	blued_config_apply_cli(&cfg, 3, argv_bad);
	ATF_CHECK_EQ_MSG(BLUED_COMPAT_BLUEZ, cfg.compat_profile,
	    "an unparsable -P must leave the effective profile untouched");
	ATF_CHECK_EQ(BLUED_ATT_ERRSEL_BLUEZ, cfg.att_error_selection);

	/* Invalid on a virgin configuration: still the shipped default. */
	blued_config_defaults(&cfg);
	blued_config_apply_cli(&cfg, 3, argv_bad);
	ATF_CHECK_EQ(BLUED_COMPAT_DEFAULT, cfg.compat_profile);
	ATF_CHECK_EQ(BLUED_ATT_ERRSEL_SPEC, cfg.att_error_selection);
	ATF_CHECK_EQ(BLUED_DB_HASH_ORDER_BLUEZ, cfg.db_hash_byte_order);
}

/*
 * -P beats the configuration file; -H then beats -P for its one behaviour;
 * and both survive the SIGHUP reload, which re-parses the file from defaults
 * and re-applies the saved argv on top.
 */
ATF_TC_WITHOUT_HEAD(compat_profile_cli_overrides_survive_reload);
ATF_TC_BODY(compat_profile_cli_overrides_survive_reload, tc)
{
	char *argv[] = { __DECONST(char *, "blued"),
	    __DECONST(char *, "-P"), __DECONST(char *, "spec"),
	    __DECONST(char *, "-H"), __DECONST(char *, "bluez"), NULL };
	struct blued_config cfg;
	char pbuf[PATH_MAX];
	const char *path = cfg_path(pbuf, sizeof(pbuf), "reload.conf");
	int pass;

	write_config(path, "compatibility_profile = \"bluez\";\n");

	/*
	 * Pass 0 is startup, pass 1 is the reload: identical sequence, which
	 * is exactly what blued_reload_config() runs.
	 */
	for (pass = 0; pass < 2; pass++) {
		blued_config_defaults(&cfg);
		ATF_REQUIRE_EQ(0, blued_config_load(&cfg, path));
		ATF_REQUIRE_EQ(BLUED_COMPAT_BLUEZ, cfg.compat_profile);
		blued_config_apply_cli(&cfg, 5, argv);

		ATF_CHECK_EQ_MSG(BLUED_COMPAT_SPEC, cfg.compat_profile,
		    "pass %d: -P must beat the configuration file", pass);
		ATF_CHECK_EQ_MSG(BLUED_ATT_ERRSEL_SPEC,
		    cfg.att_error_selection,
		    "pass %d: the profile must govern the unpinned knob",
		    pass);
		ATF_CHECK_EQ_MSG(BLUED_DB_HASH_ORDER_BLUEZ,
		    cfg.db_hash_byte_order,
		    "pass %d: -H must beat -P for the hash order", pass);
		ATF_CHECK_MSG((cfg.compat_overrides &
		    BLUED_COMPAT_OVR_DB_HASH_ORDER) != 0,
		    "pass %d: -H must mark the hash order as pinned", pass);
	}
}

/* The names used in the startup log line. */
ATF_TC_WITHOUT_HEAD(compat_profile_names);
ATF_TC_BODY(compat_profile_names, tc)
{

	ATF_CHECK_STREQ("default",
	    blued_compat_profile_name(BLUED_COMPAT_DEFAULT));
	ATF_CHECK_STREQ("spec", blued_compat_profile_name(BLUED_COMPAT_SPEC));
	ATF_CHECK_STREQ("bluez",
	    blued_compat_profile_name(BLUED_COMPAT_BLUEZ));
	/* An out-of-range code must still print something honest. */
	ATF_CHECK_STREQ("default", blued_compat_profile_name(200));

	ATF_CHECK_STREQ("spec",
	    blued_att_error_selection_name(BLUED_ATT_ERRSEL_SPEC));
	ATF_CHECK_STREQ("bluez",
	    blued_att_error_selection_name(BLUED_ATT_ERRSEL_BLUEZ));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, test_config_descriptor_and_include);
	ATF_TP_ADD_TC(tp, test_config_include_bad_range);
	ATF_TP_ADD_TC(tp, defaults_for_missing_config);
	ATF_TP_ADD_TC(tp, parses_nested_sample_shape);
	ATF_TP_ADD_TC(tp, parses_auto_adapter);
	ATF_TP_ADD_TC(tp, ignores_top_level_legacy_shape);
	ATF_TP_ADD_TC(tp, cli_overrides_config);
	ATF_TP_ADD_TC(tp, test_config_min_key_size);
	ATF_TP_ADD_TC(tp, test_config_service_uuid128);
	ATF_TP_ADD_TC(tp, test_config_key_dist_exact_tokens);
	ATF_TP_ADD_TC(tp, test_config_hex_value_odd_length);
	ATF_TP_ADD_TC(tp, test_config_malformed_ucl);

	/* GATT property/permission parsing */
	ATF_TP_ADD_TC(tp, test_parse_gatt_properties_all);
	ATF_TP_ADD_TC(tp, test_parse_gatt_properties_whitespace);
	ATF_TP_ADD_TC(tp, test_parse_gatt_permissions_all);

	/* UUID parsing */
	ATF_TP_ADD_TC(tp, test_parse_uuid_16bit);
	ATF_TP_ADD_TC(tp, test_parse_uuid_128bit);
	ATF_TP_ADD_TC(tp, test_parse_uuid_128bit_malformed);

	/* Hex value parsing */
	ATF_TP_ADD_TC(tp, test_parse_hex_value_overflow);
	ATF_TP_ADD_TC(tp, test_parse_hex_value_invalid_chars);

	/* Feature clamping */
	ATF_TP_ADD_TC(tp, test_config_rpa_timeout);
	ATF_TP_ADD_TC(tp, test_config_subrate_factor);
	ATF_TP_ADD_TC(tp, test_config_privacy_mode);
	ATF_TP_ADD_TC(tp, test_config_io_capability_all);
	ATF_TP_ADD_TC(tp, test_config_min_pairing_security);
	ATF_TP_ADD_TC(tp, test_config_reconnect_max_delay_clamp);
	ATF_TP_ADD_TC(tp, test_config_key_dist_default_is_enc_id_link);
	ATF_TP_ADD_TC(tp, test_config_key_dist_sign_token_round_trip);
	ATF_TP_ADD_TC(tp, test_config_auto_connect_max_tries_removed);

	/* Service/characteristic config parsing */
	ATF_TP_ADD_TC(tp, compat_profile_tokens);
	ATF_TP_ADD_TC(tp, compat_profile_default_preserves_shipped_behaviour);
	ATF_TP_ADD_TC(tp, compat_profile_rejects_invalid_value);
	ATF_TP_ADD_TC(tp, compat_knob_overrides_profile);
	ATF_TP_ADD_TC(tp, att_error_selection_tokens);
	ATF_TP_ADD_TC(tp, compat_profile_cli_option);
	ATF_TP_ADD_TC(tp, compat_profile_cli_overrides_survive_reload);
	ATF_TP_ADD_TC(tp, compat_profile_names);

	ATF_TP_ADD_TC(tp, test_config_service_with_char);

	/*
	 * TODO: Add test for max-array overflow — verify that
	 * config parsing correctly rejects or truncates when
	 * more devices/services/adapters are specified than the
	 * fixed-size arrays can hold (e.g. >16 devices, >8
	 * services, >8 adapters).
	 */

	return (atf_no_error());
}
