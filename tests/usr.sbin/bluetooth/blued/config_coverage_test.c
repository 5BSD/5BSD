/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Deep branch-coverage tests for the blued UCL configuration parser
 * (config.c).  These target the branches left uncovered by config_test.c,
 * config_negative_test.c and config_edge_test.c: the wrong-type second arms
 * of every section key, the array forms of the service/characteristic/adapter
 * parsers, the named-vs-unnamed body detection (phantom-service guard), the
 * partial-hex rejection, the UUID/hex boundary paths, the CLI saturation
 * arm, and the blued_config_load_fd() fault paths reachable with a real fd
 * (closed fd -> fstat error, write-only fd -> read error, >1MB file).
 *
 * Oracle: the documented UCL grammar in config.c's header comment and the
 * parse contract in config.h.  Assertions encode the SPECIFIED behavior; a
 * deviation is a finding, not something to match.
 *
 * Configs are materialized in unique mkstemp(3) files that are unlinked
 * immediately, so no working-directory litter is produced.
 */

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include <atf-c.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>

#include "att.h"
#include "att_server.h"
#include "config.h"
#include "smp.h"

/*
 * Write text to a fresh mkstemp file, load it through blued_config_load(),
 * then unlink.  cfg is reset to defaults first.  Asserts the loader returns 0.
 */
static void
load_text(struct blued_config *cfg, const char *text)
{
	char tmpl[] = "/tmp/blued_cfg_cov.XXXXXX";
	int fd;
	size_t len = strlen(text);

	fd = mkstemp(tmpl);
	ATF_REQUIRE(fd >= 0);
	if (len > 0)
		ATF_REQUIRE(write(fd, text, len) == (ssize_t)len);
	ATF_REQUIRE(close(fd) == 0);

	blued_config_defaults(cfg);
	ATF_REQUIRE_EQ(blued_config_load(cfg, tmpl), 0);

	(void)unlink(tmpl);
}

/* Create a temp file holding text; caller owns the returned path buffer. */
static int
make_temp(char *path, size_t pathsz, const char *text)
{
	int fd;
	size_t len = strlen(text);

	strlcpy(path, "/tmp/blued_cfg_fd.XXXXXX", pathsz);
	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	if (len > 0)
		ATF_REQUIRE(write(fd, text, len) == (ssize_t)len);
	return (fd);
}

/* ================================================================
 * blued_parse_hex_value(): partial-hex rejection + boundaries
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(hex_value_boundaries);
ATF_TC_BODY(hex_value_boundaries, tc)
{
	uint8_t out[8];

	/* NULL and empty => 0 bytes (valid zero-length value). */
	ATF_CHECK_EQ(blued_parse_hex_value(NULL, out, sizeof(out)), 0);
	ATF_CHECK_EQ(blued_parse_hex_value("", out, sizeof(out)), 0);

	/* Valid even-length hex. */
	ATF_CHECK_EQ(blued_parse_hex_value("0100", out, sizeof(out)), 2);
	ATF_CHECK_EQ(out[0], 0x01);
	ATF_CHECK_EQ(out[1], 0x00);

	/* Odd length => -1. */
	ATF_CHECK_EQ(blued_parse_hex_value("010", out, sizeof(out)), -1);

	/* Too long for buffer => -1 (5 bytes into a 4-byte buffer). */
	ATF_CHECK_EQ(blued_parse_hex_value("0102030405", out, 4), -1);

	/*
	 * Partial-hex bug regression: "%2x" matches a lone leading hex digit,
	 * so "0g" once slipped through as 0x00.  The isxdigit() nibble guard
	 * must now reject it.  Both nibble positions must be validated.
	 */
	ATF_CHECK_EQ(blued_parse_hex_value("0g", out, sizeof(out)), -1);
	ATF_CHECK_EQ(blued_parse_hex_value("g0", out, sizeof(out)), -1);
	ATF_CHECK_EQ(blued_parse_hex_value("zz", out, sizeof(out)), -1);
	ATF_CHECK_EQ(blued_parse_hex_value("00ff0g", out, sizeof(out)), -1);

	/* Full-buffer exact fit is accepted. */
	ATF_CHECK_EQ(blued_parse_hex_value("aabbccdd", out, 4), 4);
	ATF_CHECK_EQ(out[3], 0xdd);
}

/* ================================================================
 * blued_parse_uuid(): 16-bit, 128-bit, and every rejection path
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(uuid_parsing_all_paths);
ATF_TC_BODY(uuid_parsing_all_paths, tc)
{
	uint16_t u16;
	uint8_t u128[16];

	/* Lowercase 0x prefix. */
	u16 = 0xdead;
	ATF_CHECK_EQ(blued_parse_uuid("0x1809", &u16, u128), 0);
	ATF_CHECK_EQ(u16, 0x1809);

	/* Uppercase 0X prefix must also be accepted. */
	u16 = 0xdead;
	ATF_CHECK_EQ(blued_parse_uuid("0X180A", &u16, u128), 0);
	ATF_CHECK_EQ(u16, 0x180a);

	/* Zero is rejected (val == 0). */
	ATF_CHECK_EQ(blued_parse_uuid("0x0000", &u16, u128), -1);

	/* Above 16-bit range is rejected. */
	ATF_CHECK_EQ(blued_parse_uuid("0x10000", &u16, u128), -1);

	/* Trailing garbage after hex (endp != '\0'). */
	ATF_CHECK_EQ(blued_parse_uuid("0x18zz", &u16, u128), -1);

	/* NULL. */
	ATF_CHECK_EQ(blued_parse_uuid(NULL, &u16, u128), -1);

	/* Non-0x, wrong length (not 36) => -1. */
	ATF_CHECK_EQ(blued_parse_uuid("hello", &u16, u128), -1);

	/* 128-bit UUID, valid, stored little-endian. */
	u16 = 0xdead;
	ATF_CHECK_EQ(blued_parse_uuid(
	    "0000180d-0000-1000-8000-00805f9b34fb", &u16, u128), 0);
	ATF_CHECK_EQ(u16, 0);
	/* First display byte 0x00 lands at u128[15]; last 0xfb at u128[0]. */
	ATF_CHECK_EQ(u128[15], 0x00);
	ATF_CHECK_EQ(u128[0], 0xfb);

	/* 36 chars but not valid hex layout => sscanf != 16 => -1. */
	ATF_CHECK_EQ(blued_parse_uuid(
	    "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz", &u16, u128), -1);
}

/* ================================================================
 * blued_parse_gatt_properties/permissions(): tab trim + 1-char token
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(gatt_props_tab_and_singlechar);
ATF_TC_BODY(gatt_props_tab_and_singlechar, tc)
{
	uint8_t p;

	/* Leading tab and trailing tab around real tokens must be trimmed. */
	p = blued_parse_gatt_properties("\tread\t,\tnotify\t");
	ATF_CHECK((p & GATT_PROP_READ) != 0);
	ATF_CHECK((p & GATT_PROP_NOTIFY) != 0);

	/* Single-character token (end == token, no trailing strip). */
	ATF_CHECK_EQ(blued_parse_gatt_properties("r"), 0);

	/* Permissions: single-character token exercises the same trim guard. */
	ATF_CHECK_EQ(blued_parse_gatt_permissions("x"), 0);

	/* Permissions leading/trailing tab around a real token. */
	p = blued_parse_gatt_permissions("\twrite\t");
	ATF_CHECK((p & ATT_PERM_WRITE) != 0);
}

/* ================================================================
 * blued_config_apply_cli(): -d saturation arm (loglevel already >= 1)
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(cli_debug_saturation);
ATF_TC_BODY(cli_debug_saturation, tc)
{
	struct blued_config cfg;
	char *argv[] = {
		(char *)"blued", (char *)"-d", (char *)"-d", NULL
	};

	blued_config_defaults(&cfg);
	blued_config_apply_cli(&cfg, 3, argv);
	/* First -d: 0 -> 1.  Second -d: loglevel < 1 is false, stays 1. */
	ATF_CHECK_EQ(cfg.loglevel, 1);
}

/* ================================================================
 * blued_config_load_fd(): fault paths + valid reload
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(load_fd_negative);
ATF_TC_BODY(load_fd_negative, tc)
{
	struct blued_config cfg;

	blued_config_defaults(&cfg);
	ATF_CHECK_EQ(blued_config_load_fd(&cfg, -1), -1);
}

ATF_TC_WITHOUT_HEAD(load_fd_closed_fd_fstat_fails);
ATF_TC_BODY(load_fd_closed_fd_fstat_fails, tc)
{
	struct blued_config cfg;
	char path[64];
	int fd;

	fd = make_temp(path, sizeof(path), "general { loglevel = 2; }\n");
	ATF_REQUIRE(close(fd) == 0);
	(void)unlink(path);

	/* fd >= 0 but closed => fstat() fails => -1. */
	blued_config_defaults(&cfg);
	ATF_CHECK_EQ(blued_config_load_fd(&cfg, fd), -1);
}

ATF_TC_WITHOUT_HEAD(load_fd_empty_file);
ATF_TC_BODY(load_fd_empty_file, tc)
{
	struct blued_config cfg;
	char path[64];
	int fd;

	fd = make_temp(path, sizeof(path), "");
	/* st_size == 0 => rejected. */
	blued_config_defaults(&cfg);
	ATF_CHECK_EQ(blued_config_load_fd(&cfg, fd), -1);
	(void)close(fd);
	(void)unlink(path);
}

ATF_TC_WITHOUT_HEAD(load_fd_too_large);
ATF_TC_BODY(load_fd_too_large, tc)
{
	struct blued_config cfg;
	char path[64];
	int fd;

	fd = make_temp(path, sizeof(path), "general { loglevel = 1; }\n");
	/* Grow past the 1 MiB cap; the size gate must reject before read. */
	ATF_REQUIRE(ftruncate(fd, 2 * 1024 * 1024) == 0);
	blued_config_defaults(&cfg);
	ATF_CHECK_EQ(blued_config_load_fd(&cfg, fd), -1);
	(void)close(fd);
	(void)unlink(path);
}

ATF_TC_WITHOUT_HEAD(load_fd_write_only_read_fails);
ATF_TC_BODY(load_fd_write_only_read_fails, tc)
{
	struct blued_config cfg;
	char path[64];
	int fd, wfd;

	fd = make_temp(path, sizeof(path), "general { loglevel = 3; }\n");
	ATF_REQUIRE(close(fd) == 0);

	/* Reopen write-only: fstat/lseek succeed but read() returns -1. */
	wfd = open(path, O_WRONLY);
	ATF_REQUIRE(wfd >= 0);
	blued_config_defaults(&cfg);
	ATF_CHECK_EQ(blued_config_load_fd(&cfg, wfd), -1);
	(void)close(wfd);
	(void)unlink(path);
}

ATF_TC_WITHOUT_HEAD(load_fd_garbage_content);
ATF_TC_BODY(load_fd_garbage_content, tc)
{
	struct blued_config cfg;
	char path[64];
	int fd;

	fd = make_temp(path, sizeof(path), "this is { not valid ][ ucl @@@\n");
	blued_config_defaults(&cfg);
	/* ucl_parser_add_string() fails => -1. */
	ATF_CHECK_EQ(blued_config_load_fd(&cfg, fd), -1);
	(void)close(fd);
	(void)unlink(path);
}

ATF_TC_WITHOUT_HEAD(load_fd_valid_reload);
ATF_TC_BODY(load_fd_valid_reload, tc)
{
	struct blued_config cfg;
	char path[64];
	int fd;

	fd = make_temp(path, sizeof(path),
	    "general { loglevel = 4; }\nfeatures { eatt = false; }\n");
	blued_config_defaults(&cfg);
	ATF_CHECK_EQ(blued_config_load_fd(&cfg, fd), 0);
	ATF_CHECK_EQ(cfg.loglevel, 4);
	ATF_CHECK(!cfg.eatt);
	(void)close(fd);
	(void)unlink(path);
}

/* ================================================================
 * blued_config_load(): missing path (ENOENT ok), NULL path, empty
 * and comment-only files all succeed with defaults intact.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(load_missing_and_empty_files);
ATF_TC_BODY(load_missing_and_empty_files, tc)
{
	struct blued_config cfg;

	/* Missing file is optional => success, defaults preserved. */
	blued_config_defaults(&cfg);
	ATF_CHECK_EQ(blued_config_load(&cfg, "/nonexistent/blued.conf"), 0);
	ATF_CHECK_EQ(cfg.loglevel, 0);

	/* NULL path falls back to the default path (also absent) => success. */
	blued_config_defaults(&cfg);
	ATF_CHECK_EQ(blued_config_load(&cfg, NULL), 0);

	/* Empty file => parses to an empty root, defaults preserved. */
	load_text(&cfg, "");
	ATF_CHECK_EQ(cfg.loglevel, 0);
	ATF_CHECK_EQ(cfg.nservices, 0);

	/* Comment-only file. */
	load_text(&cfg, "# nothing here\n# still nothing\n");
	ATF_CHECK_EQ(cfg.nservices, 0);
	ATF_CHECK_EQ(cfg.ndevices, 0);
}

ATF_TC_WITHOUT_HEAD(load_parse_error_returns_minus_one);
ATF_TC_BODY(load_parse_error_returns_minus_one, tc)
{
	struct blued_config cfg;
	char tmpl[] = "/tmp/blued_cfg_bad.XXXXXX";
	int fd;
	const char *bad = "general { loglevel = ][ oops\n";

	fd = mkstemp(tmpl);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(write(fd, bad, strlen(bad)) == (ssize_t)strlen(bad));
	ATF_REQUIRE(close(fd) == 0);

	/* Non-ENOENT parse failure => -1. */
	blued_config_defaults(&cfg);
	ATF_CHECK_EQ(blued_config_load(&cfg, tmpl), -1);
	(void)unlink(tmpl);
}

/* ================================================================
 * devices: wrong-type members and per-key wrong-type second arms
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(devices_wrong_type_paths);
ATF_TC_BODY(devices_wrong_type_paths, tc)
{
	struct blued_config cfg;

	/* Device member that is not an object is skipped. */
	load_text(&cfg,
	    "devices {\n"
	    "  \"aa:bb:cc:dd:ee:ff\" = \"not-an-object\";\n"
	    "}\n");
	ATF_CHECK_EQ(cfg.ndevices, 0);

	/* Bad address => device rejected. */
	load_text(&cfg,
	    "devices {\n"
	    "  \"not-a-bd-addr\" { reconnect = true; }\n"
	    "}\n");
	ATF_CHECK_EQ(cfg.ndevices, 0);

	/*
	 * A bare device (no type/addr_type, no reconnect) exercises the
	 * val == NULL arm of the addr_type lookup and default reconnect.
	 */
	load_text(&cfg,
	    "features { reconnect = false; }\n"
	    "devices {\n"
	    "  \"11:22:33:44:55:66\" { }\n"
	    "}\n");
	ATF_REQUIRE_EQ(cfg.ndevices, 1);
	ATF_CHECK_EQ(cfg.devices[0].addr_type, BDADDR_LE_PUBLIC);
	ATF_CHECK(!cfg.devices[0].reconnect);	/* inherits features.reconnect */

	/*
	 * addr as an explicit string key, plus type/reconnect present but of
	 * the wrong UCL types (int) => the wrong-type keys are ignored while
	 * the device is still added with defaults.
	 */
	load_text(&cfg,
	    "devices {\n"
	    "  dev0 {\n"
	    "    addr = 12345;\n"		/* non-string addr => use key */
	    "    type = 7;\n"			/* non-string type ignored */
	    "    reconnect = 9;\n"		/* non-bool ignored */
	    "  }\n"
	    "}\n");
	/* key "dev0" is not a valid bd address => device rejected. */
	ATF_CHECK_EQ(cfg.ndevices, 0);

	/* Valid key address with wrong-type type/reconnect keeps defaults. */
	load_text(&cfg,
	    "devices {\n"
	    "  \"01:02:03:04:05:06\" {\n"
	    "    type = 7;\n"
	    "    reconnect = 9;\n"
	    "  }\n"
	    "}\n");
	ATF_REQUIRE_EQ(cfg.ndevices, 1);
	ATF_CHECK_EQ(cfg.devices[0].addr_type, BDADDR_LE_PUBLIC);
	ATF_CHECK(cfg.devices[0].reconnect);	/* default from features */
}

ATF_TC_WITHOUT_HEAD(devices_addr_string_and_random_type);
ATF_TC_BODY(devices_addr_string_and_random_type, tc)
{
	struct blued_config cfg;

	/* Explicit string "addr" key overrides the block key. */
	load_text(&cfg,
	    "devices {\n"
	    "  ignored {\n"
	    "    addr = \"0a:0b:0c:0d:0e:0f\";\n"
	    "    type = \"random\";\n"
	    "    reconnect = true;\n"
	    "  }\n"
	    "}\n");
	ATF_REQUIRE_EQ(cfg.ndevices, 1);
	ATF_CHECK_EQ(cfg.devices[0].addr_type, BDADDR_LE_RANDOM);
	ATF_CHECK(cfg.devices[0].reconnect);
}

ATF_TC_WITHOUT_HEAD(devices_overflow_limit);
ATF_TC_BODY(devices_overflow_limit, tc)
{
	struct blued_config cfg;
	char buf[4096];
	size_t off;
	int i;

	/* BLUED_MAX_DEVICES + 1 device blocks; the last must be dropped. */
	off = (size_t)snprintf(buf, sizeof(buf), "devices {\n");
	for (i = 0; i < BLUED_MAX_DEVICES + 1; i++)
		off += (size_t)snprintf(buf + off, sizeof(buf) - off,
		    "  \"%02x:00:00:00:00:01\" { type = \"public\"; }\n",
		    i + 1);
	(void)snprintf(buf + off, sizeof(buf) - off, "}\n");

	load_text(&cfg, buf);
	ATF_CHECK_EQ(cfg.ndevices, BLUED_MAX_DEVICES);
}

/* ================================================================
 * services: string, array, named container non-object member,
 * uuid wrong-type, and overflow (named + array).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(service_as_string_ignored);
ATF_TC_BODY(service_as_string_ignored, tc)
{
	struct blued_config cfg;

	/* service = "foo" is neither OBJECT nor ARRAY => nothing parsed. */
	load_text(&cfg, "service = \"foo\";\n");
	ATF_CHECK_EQ(cfg.nservices, 0);
}

ATF_TC_WITHOUT_HEAD(service_uuid_wrong_type);
ATF_TC_BODY(service_uuid_wrong_type, tc)
{
	struct blued_config cfg;

	/* uuid present but not a string => missing-uuid rejection. */
	load_text(&cfg,
	    "service \"S\" {\n"
	    "  uuid = 6153;\n"
	    "}\n");
	ATF_CHECK_EQ(cfg.nservices, 0);
}

ATF_TC_WITHOUT_HEAD(service_explicit_array);
ATF_TC_BODY(service_explicit_array, tc)
{
	struct blued_config cfg;

	/*
	 * Explicit UCL array of unnamed service bodies.  Array elements have
	 * no key, so svc->name is left empty (name == NULL arm).
	 */
	load_text(&cfg,
	    "service = [\n"
	    "  { uuid = \"0x1809\"; },\n"
	    "  { uuid = \"0x180a\"; }\n"
	    "];\n");
	ATF_REQUIRE_EQ(cfg.nservices, 2);
	ATF_CHECK_EQ(cfg.services[0].uuid16, 0x1809);
	ATF_CHECK_EQ(cfg.services[1].uuid16, 0x180a);
	ATF_CHECK_STREQ(cfg.services[0].name, "");
}

ATF_TC_WITHOUT_HEAD(service_array_nonobject_element);
ATF_TC_BODY(service_array_nonobject_element, tc)
{
	struct blued_config cfg;

	/* A non-object element in the service array is skipped. */
	load_text(&cfg,
	    "service = [\n"
	    "  { uuid = \"0x1809\"; },\n"
	    "  \"junk\"\n"
	    "];\n");
	ATF_CHECK_EQ(cfg.nservices, 1);
	ATF_CHECK_EQ(cfg.services[0].uuid16, 0x1809);
}

ATF_TC_WITHOUT_HEAD(service_array_overflow);
ATF_TC_BODY(service_array_overflow, tc)
{
	struct blued_config cfg;
	char buf[2048];
	size_t off;
	int i;

	/* BLUED_MAX_CONF_SERVICES + 1 array elements; last dropped. */
	off = (size_t)snprintf(buf, sizeof(buf), "service = [\n");
	for (i = 0; i < BLUED_MAX_CONF_SERVICES + 1; i++)
		off += (size_t)snprintf(buf + off, sizeof(buf) - off,
		    "  { uuid = \"0x%04x\"; },\n", 0x1800 + i);
	(void)snprintf(buf + off, sizeof(buf) - off, "];\n");

	load_text(&cfg, buf);
	ATF_CHECK_EQ(cfg.nservices, BLUED_MAX_CONF_SERVICES);
}

ATF_TC_WITHOUT_HEAD(service_named_container_nonobject_member);
ATF_TC_BODY(service_named_container_nonobject_member, tc)
{
	struct blued_config cfg;

	/*
	 * Named container: the "service" object holds no direct uuid/
	 * characteristic key, so it is iterated as a container of named
	 * services.  A non-object member ("junk") is skipped.
	 */
	load_text(&cfg,
	    "service {\n"
	    "  Good { uuid = \"0x1809\"; }\n"
	    "  junk = \"x\";\n"
	    "}\n");
	ATF_REQUIRE_EQ(cfg.nservices, 1);
	ATF_CHECK_EQ(cfg.services[0].uuid16, 0x1809);
	ATF_CHECK_STREQ(cfg.services[0].name, "Good");
}

/* ================================================================
 * named-vs-unnamed body detection + phantom-service guard
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(service_named_vs_unnamed_body);
ATF_TC_BODY(service_named_vs_unnamed_body, tc)
{
	struct blued_config cfg;

	/* Unnamed body: direct uuid => single service named by its key. */
	load_text(&cfg, "service { uuid = \"0x1809\"; }\n");
	ATF_REQUIRE_EQ(cfg.nservices, 1);
	ATF_CHECK_EQ(cfg.services[0].uuid16, 0x1809);
	ATF_CHECK_STREQ(cfg.services[0].name, "service");

	/* Named body: no direct uuid => container iterated by service name. */
	load_text(&cfg, "service \"Heart Rate\" { uuid = \"0x180d\"; }\n");
	ATF_REQUIRE_EQ(cfg.nservices, 1);
	ATF_CHECK_EQ(cfg.services[0].uuid16, 0x180d);
	ATF_CHECK_STREQ(cfg.services[0].name, "Heart Rate");
}

ATF_TC_WITHOUT_HEAD(service_phantom_guard);
ATF_TC_BODY(service_phantom_guard, tc)
{
	struct blued_config cfg;

	/*
	 * Phantom-service regression: a service body carrying a
	 * "characteristic" (which itself has a uuid) but NO service-level
	 * uuid must be routed to config_parse_service() and rejected for the
	 * missing uuid -- the characteristic's uuid must NOT be promoted into
	 * a phantom service.
	 */
	load_text(&cfg,
	    "service {\n"
	    "  characteristic {\n"
	    "    uuid = \"0xFFE1\";\n"
	    "  }\n"
	    "}\n");
	ATF_CHECK_EQ(cfg.nservices, 0);
}

/* ================================================================
 * characteristics: array form, non-object form, named container with
 * a non-object member, wrong-type keys, invalid uuid, invalid hex.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(char_explicit_array);
ATF_TC_BODY(char_explicit_array, tc)
{
	struct blued_config cfg;

	load_text(&cfg,
	    "service {\n"
	    "  uuid = \"0xFFE0\";\n"
	    "  characteristic = [\n"
	    "    { uuid = \"0xFFE1\"; properties = \"read\"; },\n"
	    "    { uuid = \"0xFFE2\"; properties = \"notify\"; }\n"
	    "  ];\n"
	    "}\n");
	ATF_REQUIRE_EQ(cfg.nservices, 1);
	ATF_REQUIRE_EQ(cfg.services[0].nchars, 2);
	ATF_CHECK_EQ(cfg.services[0].chars[0].uuid16, 0xFFE1);
	ATF_CHECK((cfg.services[0].chars[0].properties & GATT_PROP_READ) != 0);
	ATF_CHECK_EQ(cfg.services[0].chars[1].uuid16, 0xFFE2);
	/* notify => CCCD auto-added. */
	ATF_CHECK(cfg.services[0].chars[1].has_cccd);
	ATF_CHECK(!cfg.services[0].chars[0].has_cccd);
}

ATF_TC_WITHOUT_HEAD(char_nonobject_ignored);
ATF_TC_BODY(char_nonobject_ignored, tc)
{
	struct blued_config cfg;

	/* characteristic = "foo": neither object nor array => no chars. */
	load_text(&cfg,
	    "service {\n"
	    "  uuid = \"0xFFE0\";\n"
	    "  characteristic = \"foo\";\n"
	    "}\n");
	ATF_REQUIRE_EQ(cfg.nservices, 1);
	ATF_CHECK_EQ(cfg.services[0].nchars, 0);
}

ATF_TC_WITHOUT_HEAD(char_array_nonobject_element);
ATF_TC_BODY(char_array_nonobject_element, tc)
{
	struct blued_config cfg;

	/* Non-object element inside a characteristic array is skipped. */
	load_text(&cfg,
	    "service {\n"
	    "  uuid = \"0xFFE0\";\n"
	    "  characteristic = [\n"
	    "    { uuid = \"0xFFE1\"; },\n"
	    "    \"junk\"\n"
	    "  ];\n"
	    "}\n");
	ATF_REQUIRE_EQ(cfg.nservices, 1);
	ATF_CHECK_EQ(cfg.services[0].nchars, 1);
	ATF_CHECK_EQ(cfg.services[0].chars[0].uuid16, 0xFFE1);
}

ATF_TC_WITHOUT_HEAD(char_named_container_nonobject_member);
ATF_TC_BODY(char_named_container_nonobject_member, tc)
{
	struct blued_config cfg;

	/*
	 * "characteristic" object with no direct uuid => form (a) container;
	 * iterate named sub-objects.  A non-object member ("junk") is skipped,
	 * the real characteristic ("Real") is parsed.
	 */
	load_text(&cfg,
	    "service {\n"
	    "  uuid = \"0xFFE0\";\n"
	    "  characteristic {\n"
	    "    junk = \"x\";\n"
	    "    Real { uuid = \"0xFFE1\"; }\n"
	    "  }\n"
	    "}\n");
	ATF_REQUIRE_EQ(cfg.nservices, 1);
	ATF_REQUIRE_EQ(cfg.services[0].nchars, 1);
	ATF_CHECK_EQ(cfg.services[0].chars[0].uuid16, 0xFFE1);
}

ATF_TC_WITHOUT_HEAD(char_wrong_type_keys);
ATF_TC_BODY(char_wrong_type_keys, tc)
{
	struct blued_config cfg;

	/*
	 * uuid valid; properties/permissions/value present but wrong UCL type
	 * (int) => those keys ignored, characteristic still added.
	 */
	load_text(&cfg,
	    "service {\n"
	    "  uuid = \"0xFFE0\";\n"
	    "  characteristic {\n"
	    "    uuid = \"0xFFE1\";\n"
	    "    properties = 5;\n"
	    "    permissions = 6;\n"
	    "    value = 7;\n"
	    "  }\n"
	    "}\n");
	ATF_REQUIRE_EQ(cfg.nservices, 1);
	ATF_REQUIRE_EQ(cfg.services[0].nchars, 1);
	ATF_CHECK_EQ(cfg.services[0].chars[0].properties, 0);
	ATF_CHECK_EQ(cfg.services[0].chars[0].permissions, 0);
	ATF_CHECK_EQ(cfg.services[0].chars[0].initial_value_len, 0);
}

ATF_TC_WITHOUT_HEAD(char_uuid_missing_and_invalid);
ATF_TC_BODY(char_uuid_missing_and_invalid, tc)
{
	struct blued_config cfg;

	/* uuid present but not a string => characteristic rejected. */
	load_text(&cfg,
	    "service {\n"
	    "  uuid = \"0xFFE0\";\n"
	    "  characteristic {\n"
	    "    uuid = 123;\n"
	    "  }\n"
	    "}\n");
	ATF_REQUIRE_EQ(cfg.nservices, 1);
	ATF_CHECK_EQ(cfg.services[0].nchars, 0);

	/* uuid present, string, but invalid => characteristic rejected. */
	load_text(&cfg,
	    "service {\n"
	    "  uuid = \"0xFFE0\";\n"
	    "  characteristic {\n"
	    "    uuid = \"0x0000\";\n"
	    "  }\n"
	    "}\n");
	ATF_REQUIRE_EQ(cfg.nservices, 1);
	ATF_CHECK_EQ(cfg.services[0].nchars, 0);
}

ATF_TC_WITHOUT_HEAD(char_invalid_hex_value_rejected);
ATF_TC_BODY(char_invalid_hex_value_rejected, tc)
{
	struct blued_config cfg;

	/*
	 * Invalid hex "0g" in a characteristic value must reject that
	 * characteristic (len < 0 arm), not silently accept a partial byte.
	 */
	load_text(&cfg,
	    "service {\n"
	    "  uuid = \"0xFFE0\";\n"
	    "  characteristic {\n"
	    "    uuid = \"0xFFE1\";\n"
	    "    value = \"0g\";\n"
	    "  }\n"
	    "}\n");
	ATF_REQUIRE_EQ(cfg.nservices, 1);
	ATF_CHECK_EQ(cfg.services[0].nchars, 0);

	/* A valid hex value is accepted and stored. */
	load_text(&cfg,
	    "service {\n"
	    "  uuid = \"0xFFE0\";\n"
	    "  characteristic {\n"
	    "    uuid = \"0xFFE1\";\n"
	    "    value = \"01ff\";\n"
	    "  }\n"
	    "}\n");
	ATF_REQUIRE_EQ(cfg.nservices, 1);
	ATF_REQUIRE_EQ(cfg.services[0].nchars, 1);
	ATF_CHECK_EQ(cfg.services[0].chars[0].initial_value_len, 2);
	ATF_CHECK_EQ(cfg.services[0].chars[0].initial_value[0], 0x01);
	ATF_CHECK_EQ(cfg.services[0].chars[0].initial_value[1], 0xff);
}

ATF_TC_WITHOUT_HEAD(char_overflow_limit);
ATF_TC_BODY(char_overflow_limit, tc)
{
	struct blued_config cfg;
	char buf[2048];
	size_t off;
	int i;

	/* BLUED_MAX_CONF_CHARS + 1 characteristics via explicit array. */
	off = (size_t)snprintf(buf, sizeof(buf),
	    "service {\n  uuid = \"0xFFE0\";\n  characteristic = [\n");
	for (i = 0; i < BLUED_MAX_CONF_CHARS + 1; i++)
		off += (size_t)snprintf(buf + off, sizeof(buf) - off,
		    "    { uuid = \"0x%04x\"; },\n", 0xFF00 + i);
	(void)snprintf(buf + off, sizeof(buf) - off, "  ];\n}\n");

	load_text(&cfg, buf);
	ATF_REQUIRE_EQ(cfg.nservices, 1);
	ATF_CHECK_EQ(cfg.services[0].nchars, BLUED_MAX_CONF_CHARS);
}

/* ================================================================
 * adapters: non-auto single string, int (neither string nor array),
 * "auto" element mid-array, and overflow.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(adapters_single_string_non_auto);
ATF_TC_BODY(adapters_single_string_non_auto, tc)
{
	struct blued_config cfg;

	/*
	 * adapters as a bare non-"auto" string: the code only resets to
	 * auto-detect when the string is "auto"; any other string leaves
	 * nadapters unchanged (no adapter is recorded from a scalar string).
	 */
	load_text(&cfg, "adapters = \"ubt0\";\n");
	ATF_CHECK_EQ(cfg.nadapters, 0);

	/* adapters = "auto" resets to auto-detect. */
	load_text(&cfg, "adapters = \"auto\";\n");
	ATF_CHECK_EQ(cfg.nadapters, 0);
}

ATF_TC_WITHOUT_HEAD(adapters_wrong_scalar_type);
ATF_TC_BODY(adapters_wrong_scalar_type, tc)
{
	struct blued_config cfg;

	/* adapters as an int: neither STRING nor ARRAY => ignored. */
	load_text(&cfg, "adapters = 42;\n");
	ATF_CHECK_EQ(cfg.nadapters, 0);
}

ATF_TC_WITHOUT_HEAD(adapters_array_auto_element);
ATF_TC_BODY(adapters_array_auto_element, tc)
{
	struct blued_config cfg;

	/* An "auto" element inside the array forces auto-detect and stops. */
	load_text(&cfg, "adapters = [\"ubt0\", \"auto\", \"ubt2\"];\n");
	ATF_CHECK_EQ(cfg.nadapters, 0);
}

ATF_TC_WITHOUT_HEAD(adapters_array_overflow);
ATF_TC_BODY(adapters_array_overflow, tc)
{
	struct blued_config cfg;
	char buf[512];
	size_t off;
	int i;

	off = (size_t)snprintf(buf, sizeof(buf), "adapters = [");
	for (i = 0; i < 10; i++)		/* capacity is 8 */
		off += (size_t)snprintf(buf + off, sizeof(buf) - off,
		    "%s\"ubt%d\"", i ? ", " : "", i);
	(void)snprintf(buf + off, sizeof(buf) - off, "];\n");

	load_text(&cfg, buf);
	ATF_CHECK_EQ(cfg.nadapters, 8);
}

/* ================================================================
 * general/features/security: clamps (min/max/in-range) and the
 * privacy_mode string mapping + io_capability mapping (oracle).
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(general_loglevel_clamp);
ATF_TC_BODY(general_loglevel_clamp, tc)
{
	struct blued_config cfg;

	load_text(&cfg, "general { loglevel = 99; }\n");
	ATF_CHECK_EQ(cfg.loglevel, 5);		/* clamped to max */
	load_text(&cfg, "general { loglevel = -4; }\n");
	ATF_CHECK_EQ(cfg.loglevel, 0);		/* clamped to min */
	load_text(&cfg, "general { loglevel = 3; }\n");
	ATF_CHECK_EQ(cfg.loglevel, 3);		/* in range */
}

ATF_TC_WITHOUT_HEAD(security_min_key_size_clamp);
ATF_TC_BODY(security_min_key_size_clamp, tc)
{
	struct blued_config cfg;

	load_text(&cfg, "security { min_key_size = 4; }\n");
	ATF_CHECK_EQ(cfg.min_key_size, 7);	/* clamped to floor 7 */
	load_text(&cfg, "security { min_key_size = 32; }\n");
	ATF_CHECK_EQ(cfg.min_key_size, 16);	/* clamped to ceil 16 */
	load_text(&cfg, "security { min_key_size = 10; }\n");
	ATF_CHECK_EQ(cfg.min_key_size, 10);	/* in range */
}

ATF_TC_WITHOUT_HEAD(features_numeric_clamps);
ATF_TC_BODY(features_numeric_clamps, tc)
{
	struct blued_config cfg;

	load_text(&cfg, "features { reconnect_max_delay = 0; }\n");
	ATF_CHECK_EQ(cfg.reconnect_max_delay, 1);
	load_text(&cfg, "features { reconnect_max_delay = 999999; }\n");
	ATF_CHECK_EQ(cfg.reconnect_max_delay, 3600);
	load_text(&cfg, "features { rpa_timeout = 0; }\n");
	ATF_CHECK_EQ(cfg.rpa_timeout, 1);
	load_text(&cfg, "features { rpa_timeout = 999999; }\n");
	ATF_CHECK_EQ(cfg.rpa_timeout, 3600);
}

ATF_TC_WITHOUT_HEAD(features_privacy_mode_strings);
ATF_TC_BODY(features_privacy_mode_strings, tc)
{
	struct blued_config cfg;

	load_text(&cfg, "features { privacy_mode = \"network\"; }\n");
	ATF_CHECK_EQ(cfg.privacy_mode, 0);
	load_text(&cfg, "features { privacy_mode = \"device\"; }\n");
	ATF_CHECK_EQ(cfg.privacy_mode, 1);
	/* Unknown string leaves the default (device=1) untouched. */
	load_text(&cfg, "features { privacy_mode = \"bogus\"; }\n");
	ATF_CHECK_EQ(cfg.privacy_mode, 1);
}

ATF_TC_WITHOUT_HEAD(security_io_capability_mapping);
ATF_TC_BODY(security_io_capability_mapping, tc)
{
	struct blued_config cfg;

	load_text(&cfg, "security { io_capability = \"display_only\"; }\n");
	ATF_CHECK_EQ(cfg.io_capability, SMP_IO_DISPLAY_ONLY);
	load_text(&cfg, "security { io_capability = \"display_yesno\"; }\n");
	ATF_CHECK_EQ(cfg.io_capability, SMP_IO_DISPLAY_YESNO);
	load_text(&cfg, "security { io_capability = \"keyboard_only\"; }\n");
	ATF_CHECK_EQ(cfg.io_capability, SMP_IO_KEYBOARD_ONLY);
	load_text(&cfg, "security { io_capability = \"none\"; }\n");
	ATF_CHECK_EQ(cfg.io_capability, SMP_IO_NO_INPUT_NO_OUTPUT);
	load_text(&cfg,
	    "security { io_capability = \"no_input_no_output\"; }\n");
	ATF_CHECK_EQ(cfg.io_capability, SMP_IO_NO_INPUT_NO_OUTPUT);
	load_text(&cfg, "security { io_capability = \"keyboard_display\"; }\n");
	ATF_CHECK_EQ(cfg.io_capability, SMP_IO_KEYBOARD_DISPLAY);
	/* Unknown => falls back to keyboard_display. */
	load_text(&cfg, "security { io_capability = \"bogus\"; }\n");
	ATF_CHECK_EQ(cfg.io_capability, SMP_IO_KEYBOARD_DISPLAY);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, hex_value_boundaries);
	ATF_TP_ADD_TC(tp, uuid_parsing_all_paths);
	ATF_TP_ADD_TC(tp, gatt_props_tab_and_singlechar);
	ATF_TP_ADD_TC(tp, cli_debug_saturation);
	ATF_TP_ADD_TC(tp, load_fd_negative);
	ATF_TP_ADD_TC(tp, load_fd_closed_fd_fstat_fails);
	ATF_TP_ADD_TC(tp, load_fd_empty_file);
	ATF_TP_ADD_TC(tp, load_fd_too_large);
	ATF_TP_ADD_TC(tp, load_fd_write_only_read_fails);
	ATF_TP_ADD_TC(tp, load_fd_garbage_content);
	ATF_TP_ADD_TC(tp, load_fd_valid_reload);
	ATF_TP_ADD_TC(tp, load_missing_and_empty_files);
	ATF_TP_ADD_TC(tp, load_parse_error_returns_minus_one);
	ATF_TP_ADD_TC(tp, devices_wrong_type_paths);
	ATF_TP_ADD_TC(tp, devices_addr_string_and_random_type);
	ATF_TP_ADD_TC(tp, devices_overflow_limit);
	ATF_TP_ADD_TC(tp, service_as_string_ignored);
	ATF_TP_ADD_TC(tp, service_uuid_wrong_type);
	ATF_TP_ADD_TC(tp, service_explicit_array);
	ATF_TP_ADD_TC(tp, service_array_nonobject_element);
	ATF_TP_ADD_TC(tp, service_array_overflow);
	ATF_TP_ADD_TC(tp, service_named_container_nonobject_member);
	ATF_TP_ADD_TC(tp, service_named_vs_unnamed_body);
	ATF_TP_ADD_TC(tp, service_phantom_guard);
	ATF_TP_ADD_TC(tp, char_explicit_array);
	ATF_TP_ADD_TC(tp, char_nonobject_ignored);
	ATF_TP_ADD_TC(tp, char_array_nonobject_element);
	ATF_TP_ADD_TC(tp, char_named_container_nonobject_member);
	ATF_TP_ADD_TC(tp, char_wrong_type_keys);
	ATF_TP_ADD_TC(tp, char_uuid_missing_and_invalid);
	ATF_TP_ADD_TC(tp, char_invalid_hex_value_rejected);
	ATF_TP_ADD_TC(tp, char_overflow_limit);
	ATF_TP_ADD_TC(tp, adapters_single_string_non_auto);
	ATF_TP_ADD_TC(tp, adapters_wrong_scalar_type);
	ATF_TP_ADD_TC(tp, adapters_array_auto_element);
	ATF_TP_ADD_TC(tp, adapters_array_overflow);
	ATF_TP_ADD_TC(tp, general_loglevel_clamp);
	ATF_TP_ADD_TC(tp, security_min_key_size_clamp);
	ATF_TP_ADD_TC(tp, features_numeric_clamps);
	ATF_TP_ADD_TC(tp, features_privacy_mode_strings);
	ATF_TP_ADD_TC(tp, security_io_capability_mapping);

	return (atf_no_error());
}
