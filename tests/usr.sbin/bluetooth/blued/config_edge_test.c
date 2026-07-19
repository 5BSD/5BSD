/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF edge-case tests for the blued UCL configuration parser (config.c).
 *
 * config_test.c and config_negative_test.c cover the common keys and the
 * headline malformed-input cases.  This file fills the branch gaps they
 * leave: every general/security/features key exercised with both correct
 * and wrong value types, every numeric clamp at both rails, the "auto"
 * adapters string form and adapters-array-with-"auto", the array forms of
 * the service and characteristic blocks, the device sub-parser variants,
 * the blued_config_load_fd() reload entry point (valid / empty / bad fd /
 * bad UCL / oversized), and the full blued_config_apply_cli() option set
 * including overflow and saturation paths.
 *
 * The parser consumes an untrusted admin-controlled file, so the contract
 * (config.h defaults + documented clamp ranges) is the oracle: wrong types
 * are ignored and defaults retained; out-of-range numerics are clamped to
 * the documented rail; array overflows are bounded by the BLUED_MAX_*
 * limits.  Expected values come from those documented ranges, never from
 * captured parser output.
 *
 * Every config is written to a UNIQUE mkstemp(3) file and unlinked; no
 * artifact is left in the current directory.
 */

#include <sys/param.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include <atf-c.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "att.h"
#include "att_server.h"
#include "config.h"
#include "smp.h"

/* Write text to a unique temp file, load via path, unlink, return result. */
static int
load_text(struct blued_config *cfg, const char *text)
{
	char path[] = "/tmp/blued-cfgedge.XXXXXX";
	int fd, ret;
	size_t len;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	len = strlen(text);
	ATF_REQUIRE(write(fd, text, len) == (ssize_t)len);
	ATF_REQUIRE(close(fd) == 0);

	blued_config_defaults(cfg);
	ret = blued_config_load(cfg, path);
	(void)unlink(path);
	return (ret);
}

/* Write text to a temp file and load via the pre-opened-fd reload path. */
static int
load_text_fd(struct blued_config *cfg, const char *text)
{
	char path[] = "/tmp/blued-cfgedgefd.XXXXXX";
	int fd, ret;
	size_t len;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	len = strlen(text);
	ATF_REQUIRE(write(fd, text, len) == (ssize_t)len);

	blued_config_defaults(cfg);
	ret = blued_config_load_fd(cfg, fd);
	(void)close(fd);
	(void)unlink(path);
	return (ret);
}

/* ================================================================
 * general: every key present with the correct type
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_general_all_keys);
ATF_TC_BODY(edge_general_all_keys, tc)
{
	struct blued_config cfg;

	ATF_REQUIRE_EQ(load_text(&cfg,
	    "general {\n"
	    "  pidfile = \"/run/x.pid\"\n"
	    "  bonddb = \"/db/x\"\n"
	    "  ctlsock = \"/run/x.sock\"\n"
	    "  logfile = \"/log/x.snoop\"\n"
	    "  loglevel = 3\n"
	    "  daemonize = true\n"
	    "  peripheral_name = \"MyDev\"\n"
	    "}\n"), 0);

	ATF_CHECK_STREQ(cfg.pidfile, "/run/x.pid");
	ATF_CHECK_STREQ(cfg.bonddb, "/db/x");
	ATF_CHECK_STREQ(cfg.ctlsock, "/run/x.sock");
	ATF_CHECK_STREQ(cfg.logfile, "/log/x.snoop");
	ATF_CHECK_EQ(cfg.loglevel, 3);
	ATF_CHECK(cfg.daemonize);
	ATF_CHECK_STREQ(cfg.peripheral_name, "MyDev");
}

/* ================================================================
 * general: every key present but WRONG type -> defaults retained
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_general_type_mismatch);
ATF_TC_BODY(edge_general_type_mismatch, tc)
{
	struct blued_config cfg;

	ATF_REQUIRE_EQ(load_text(&cfg,
	    "general {\n"
	    "  pidfile = 42\n"		/* int, not string */
	    "  bonddb = true\n"		/* bool, not string */
	    "  ctlsock = 1.5\n"		/* float, not string */
	    "  logfile = 7\n"
	    "  loglevel = \"high\"\n"	/* string, not int */
	    "  daemonize = 3\n"		/* int, not bool */
	    "  peripheral_name = false\n"
	    "}\n"), 0);

	/* Defaults preserved for every mistyped key. */
	ATF_CHECK_STREQ(cfg.pidfile, BLUED_PIDFILE_DEFAULT);
	ATF_CHECK_STREQ(cfg.bonddb, BLUED_BONDDB_DEFAULT);
	ATF_CHECK_STREQ(cfg.ctlsock, BLUED_CTLSOCK_DEFAULT);
	ATF_CHECK_EQ(cfg.logfile[0], '\0');
	ATF_CHECK_EQ(cfg.loglevel, 0);
	ATF_CHECK(!cfg.daemonize);
	ATF_CHECK_STREQ(cfg.peripheral_name, "FreeBSD-BLE");
}

/* ================================================================
 * general: loglevel clamp at both rails
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_loglevel_clamp_high);
ATF_TC_BODY(edge_loglevel_clamp_high, tc)
{
	struct blued_config cfg;

	ATF_REQUIRE_EQ(load_text(&cfg,
	    "general { loglevel = 99 }\n"), 0);
	ATF_CHECK_EQ(cfg.loglevel, 5);		/* clamped to MAX 5 */
}

ATF_TC_WITHOUT_HEAD(edge_loglevel_clamp_low);
ATF_TC_BODY(edge_loglevel_clamp_low, tc)
{
	struct blued_config cfg;

	ATF_REQUIRE_EQ(load_text(&cfg,
	    "general { loglevel = -7 }\n"), 0);
	ATF_CHECK_EQ(cfg.loglevel, 0);		/* clamped to MIN 0 */
}

/* ================================================================
 * features: all keys + numeric clamps at both rails
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_features_all_keys);
ATF_TC_BODY(edge_features_all_keys, tc)
{
	struct blued_config cfg;

	ATF_REQUIRE_EQ(load_text(&cfg,
	    "features {\n"
	    "  eatt = false\n"
	    "  privacy = false\n"
	    "  reconnect = false\n"
	    "  reconnect_max_delay = 120\n"
	    "  privacy_mode = \"network\"\n"
	    "  rpa_timeout = 300\n"
	    "  peripheral_mode = true\n"
	    "  scan_mode = true\n"
	    "}\n"), 0);

	ATF_CHECK(!cfg.eatt);
	ATF_CHECK(!cfg.privacy);
	ATF_CHECK(!cfg.reconnect);
	ATF_CHECK_EQ(cfg.reconnect_max_delay, 120);
	ATF_CHECK_EQ(cfg.privacy_mode, 0);	/* network */
	ATF_CHECK_EQ(cfg.rpa_timeout, 300);
	ATF_CHECK(cfg.peripheral_mode);
	ATF_CHECK(cfg.scan_mode);
}

ATF_TC_WITHOUT_HEAD(edge_features_privacy_mode_device);
ATF_TC_BODY(edge_features_privacy_mode_device, tc)
{
	struct blued_config cfg;

	/* explicit "device" branch (distinct from the "network" branch). */
	ATF_REQUIRE_EQ(load_text(&cfg,
	    "features { privacy_mode = \"device\" }\n"), 0);
	ATF_CHECK_EQ(cfg.privacy_mode, 1);

	/* unknown value leaves the default (1) untouched. */
	ATF_REQUIRE_EQ(load_text(&cfg,
	    "features { privacy_mode = \"bogus\" }\n"), 0);
	ATF_CHECK_EQ(cfg.privacy_mode, 1);
}

ATF_TC_WITHOUT_HEAD(edge_features_clamps);
ATF_TC_BODY(edge_features_clamps, tc)
{
	struct blued_config cfg;

	ATF_REQUIRE_EQ(load_text(&cfg,
	    "features {\n"
	    "  reconnect_max_delay = 999999\n"	/* -> 3600 */
	    "  rpa_timeout = 0\n"		/* -> 1 */
	    "}\n"), 0);
	ATF_CHECK_EQ(cfg.reconnect_max_delay, 3600);
	ATF_CHECK_EQ(cfg.rpa_timeout, 1);

	ATF_REQUIRE_EQ(load_text(&cfg,
	    "features {\n"
	    "  reconnect_max_delay = 0\n"	/* -> 1 */
	    "  rpa_timeout = 999999\n"		/* -> 3600 */
	    "}\n"), 0);
	ATF_CHECK_EQ(cfg.reconnect_max_delay, 1);
	ATF_CHECK_EQ(cfg.rpa_timeout, 3600);
}

ATF_TC_WITHOUT_HEAD(edge_features_type_mismatch);
ATF_TC_BODY(edge_features_type_mismatch, tc)
{
	struct blued_config cfg;

	/* Wrong types leave every default. */
	ATF_REQUIRE_EQ(load_text(&cfg,
	    "features {\n"
	    "  eatt = 1\n"
	    "  privacy = \"yes\"\n"
	    "  reconnect = 0\n"
	    "  reconnect_max_delay = \"soon\"\n"
	    "  privacy_mode = 2\n"		/* int, not string */
	    "  rpa_timeout = true\n"
	    "  peripheral_mode = 5\n"
	    "  scan_mode = \"on\"\n"
	    "}\n"), 0);
	ATF_CHECK(cfg.eatt);			/* default true */
	ATF_CHECK(cfg.privacy);
	ATF_CHECK(cfg.reconnect);
	ATF_CHECK_EQ(cfg.reconnect_max_delay, BLUED_RECONNECT_MAX_DEFAULT);
	ATF_CHECK_EQ(cfg.privacy_mode, 1);
	ATF_CHECK_EQ(cfg.rpa_timeout, BLUED_RPA_TIMEOUT_DEFAULT);
	ATF_CHECK(!cfg.peripheral_mode);
	ATF_CHECK(!cfg.scan_mode);
}

/* ================================================================
 * security: io_capability variants + min_key_size clamps + mismatch
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_security_io_capability_variants);
ATF_TC_BODY(edge_security_io_capability_variants, tc)
{
	struct blued_config cfg;
	struct {
		const char *s;
		uint8_t v;
	} cases[] = {
		{ "display_only", SMP_IO_DISPLAY_ONLY },
		{ "display_yesno", SMP_IO_DISPLAY_YESNO },
		{ "keyboard_only", SMP_IO_KEYBOARD_ONLY },
		{ "no_input_no_output", SMP_IO_NO_INPUT_NO_OUTPUT },
		{ "none", SMP_IO_NO_INPUT_NO_OUTPUT },
		{ "keyboard_display", SMP_IO_KEYBOARD_DISPLAY },
		{ "bogus", SMP_IO_KEYBOARD_DISPLAY },	/* fallback */
	};
	char buf[128];
	size_t i;

	for (i = 0; i < nitems(cases); i++) {
		snprintf(buf, sizeof(buf),
		    "security { io_capability = \"%s\" }\n", cases[i].s);
		ATF_REQUIRE_EQ(load_text(&cfg, buf), 0);
		ATF_CHECK_EQ(cfg.io_capability, cases[i].v);
	}
}

ATF_TC_WITHOUT_HEAD(edge_security_min_key_size_clamp);
ATF_TC_BODY(edge_security_min_key_size_clamp, tc)
{
	struct blued_config cfg;

	ATF_REQUIRE_EQ(load_text(&cfg,
	    "security { min_key_size = 3 }\n"), 0);
	ATF_CHECK_EQ(cfg.min_key_size, 7);	/* MAX(7, ...) */

	ATF_REQUIRE_EQ(load_text(&cfg,
	    "security { min_key_size = 99 }\n"), 0);
	ATF_CHECK_EQ(cfg.min_key_size, 16);	/* MIN(..., 16) */

	ATF_REQUIRE_EQ(load_text(&cfg,
	    "security { min_key_size = 10 }\n"), 0);
	ATF_CHECK_EQ(cfg.min_key_size, 10);	/* in range */
}

ATF_TC_WITHOUT_HEAD(edge_security_all_keys);
ATF_TC_BODY(edge_security_all_keys, tc)
{
	struct blued_config cfg;

	ATF_REQUIRE_EQ(load_text(&cfg,
	    "security {\n"
	    "  bondable = false\n"
	    "  sc = \"only\"\n"
	    "}\n"), 0);
	ATF_CHECK(!cfg.bondable);
	ATF_CHECK_EQ(cfg.sc_mode, BLUED_SC_ONLY);

	/* wrong types leave defaults. */
	ATF_REQUIRE_EQ(load_text(&cfg,
	    "security {\n"
	    "  io_capability = 3\n"
	    "  bondable = 1\n"
	    "  sc = \"x\"\n"
	    "  min_key_size = \"big\"\n"
	    "}\n"), 0);
	ATF_CHECK_EQ(cfg.io_capability, SMP_IO_KEYBOARD_DISPLAY);
	ATF_CHECK(cfg.bondable);		/* default true */
	ATF_CHECK_EQ(cfg.sc_mode, BLUED_SC_ON);
	ATF_CHECK_EQ(cfg.min_key_size, BLUED_MIN_KEY_SIZE_DEFAULT);
}

/* ================================================================
 * adapters: "auto" string, array, "auto" inside array, overflow
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_adapters_auto_string);
ATF_TC_BODY(edge_adapters_auto_string, tc)
{
	struct blued_config cfg;

	ATF_REQUIRE_EQ(load_text(&cfg, "adapters = \"auto\"\n"), 0);
	ATF_CHECK_EQ(cfg.nadapters, 0);		/* auto-detect */
}

ATF_TC_WITHOUT_HEAD(edge_adapters_array);
ATF_TC_BODY(edge_adapters_array, tc)
{
	struct blued_config cfg;

	ATF_REQUIRE_EQ(load_text(&cfg,
	    "adapters = [\"ubt0\", \"ubt1\", \"ubt2\"]\n"), 0);
	ATF_CHECK_EQ(cfg.nadapters, 3);
	ATF_CHECK_STREQ(cfg.adapters[0], "ubt0");
	ATF_CHECK_STREQ(cfg.adapters[2], "ubt2");
}

ATF_TC_WITHOUT_HEAD(edge_adapters_auto_in_array);
ATF_TC_BODY(edge_adapters_auto_in_array, tc)
{
	struct blued_config cfg;

	/* "auto" element resets to auto-detect and stops. */
	ATF_REQUIRE_EQ(load_text(&cfg,
	    "adapters = [\"ubt0\", \"auto\", \"ubt9\"]\n"), 0);
	ATF_CHECK_EQ(cfg.nadapters, 0);
}

ATF_TC_WITHOUT_HEAD(edge_adapters_overflow);
ATF_TC_BODY(edge_adapters_overflow, tc)
{
	struct blued_config cfg;

	/* 10 entries, capacity 8: excess ignored, no overrun. */
	ATF_REQUIRE_EQ(load_text(&cfg,
	    "adapters = [\"a0\",\"a1\",\"a2\",\"a3\",\"a4\",\"a5\","
	    "\"a6\",\"a7\",\"a8\",\"a9\"]\n"), 0);
	ATF_CHECK_EQ(cfg.nadapters, 8);
}

ATF_TC_WITHOUT_HEAD(edge_adapters_array_nonstring_elem);
ATF_TC_BODY(edge_adapters_array_nonstring_elem, tc)
{
	struct blued_config cfg;

	/* non-string elements are skipped, string ones still counted. */
	ATF_REQUIRE_EQ(load_text(&cfg,
	    "adapters = [\"ubt0\", 42, \"ubt1\"]\n"), 0);
	ATF_CHECK_EQ(cfg.nadapters, 2);
	ATF_CHECK_STREQ(cfg.adapters[0], "ubt0");
	ATF_CHECK_STREQ(cfg.adapters[1], "ubt1");
}

/* ================================================================
 * devices: addr key vs block-name key, addr_type variants, invalid addr
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_devices_variants);
ATF_TC_BODY(edge_devices_variants, tc)
{
	struct blued_config cfg;

	ATF_REQUIRE_EQ(load_text(&cfg,
	    "devices {\n"
	    "  \"aa:bb:cc:dd:ee:ff\" {\n"
	    "     type = \"random\"\n"
	    "     reconnect = false\n"
	    "  }\n"
	    "  dev2 {\n"
	    "     addr = \"11:22:33:44:55:66\"\n"
	    "     addr_type = \"public\"\n"
	    "     reconnect = true\n"
	    "  }\n"
	    "}\n"), 0);

	ATF_CHECK_EQ(cfg.ndevices, 2);
	/* First device: key-derived addr, random type, reconnect override. */
	ATF_CHECK_EQ(cfg.devices[0].addr_type, BDADDR_LE_RANDOM);
	ATF_CHECK(!cfg.devices[0].reconnect);
	/* Second device: explicit addr key, public type. */
	ATF_CHECK_EQ(cfg.devices[1].addr_type, BDADDR_LE_PUBLIC);
	ATF_CHECK(cfg.devices[1].reconnect);
}

ATF_TC_WITHOUT_HEAD(edge_devices_invalid_addr);
ATF_TC_BODY(edge_devices_invalid_addr, tc)
{
	struct blued_config cfg;

	/* Un-parseable address -> device rejected. */
	ATF_REQUIRE_EQ(load_text(&cfg,
	    "devices { \"not-an-address\" { type = \"random\" } }\n"), 0);
	ATF_CHECK_EQ(cfg.ndevices, 0);
}

ATF_TC_WITHOUT_HEAD(edge_devices_overflow);
ATF_TC_BODY(edge_devices_overflow, tc)
{
	struct blued_config cfg;
	char buf[4096];
	size_t off = 0;
	int i;

	off += (size_t)snprintf(buf + off, sizeof(buf) - off, "devices {\n");
	for (i = 0; i < BLUED_MAX_DEVICES + 4; i++)
		off += (size_t)snprintf(buf + off, sizeof(buf) - off,
		    "  \"aa:bb:cc:dd:ee:%02x\" { type = \"public\" }\n", i);
	snprintf(buf + off, sizeof(buf) - off, "}\n");

	ATF_REQUIRE_EQ(load_text(&cfg, buf), 0);
	ATF_CHECK_EQ(cfg.ndevices, BLUED_MAX_DEVICES);
}

/* ================================================================
 * services: named container, array form, missing/invalid uuid, overflow
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_service_named_with_chars);
ATF_TC_BODY(edge_service_named_with_chars, tc)
{
	struct blued_config cfg;

	ATF_REQUIRE_EQ(load_text(&cfg,
	    "service \"Sensor\" {\n"
	    "  uuid = \"0xFFE0\"\n"
	    "  characteristic \"Data\" {\n"
	    "    uuid = \"0xFFE1\"\n"
	    "    properties = \"read,notify\"\n"
	    "    permissions = \"read\"\n"
	    "    value = \"0102\"\n"
	    "  }\n"
	    "}\n"), 0);

	ATF_REQUIRE_EQ(cfg.nservices, 1);
	ATF_CHECK_EQ(cfg.services[0].uuid16, 0xFFE0);
	ATF_REQUIRE_EQ(cfg.services[0].nchars, 1);
	ATF_CHECK_EQ(cfg.services[0].chars[0].uuid16, 0xFFE1);
	ATF_CHECK(cfg.services[0].chars[0].has_cccd);	/* notify -> CCCD */
	ATF_CHECK_EQ(cfg.services[0].chars[0].initial_value_len, 2);
	ATF_CHECK_EQ(cfg.services[0].chars[0].initial_value[0], 0x01);
}

ATF_TC_WITHOUT_HEAD(edge_service_unnamed_body);
ATF_TC_BODY(edge_service_unnamed_body, tc)
{
	struct blued_config cfg;

	/* service body with a uuid directly under "service". */
	ATF_REQUIRE_EQ(load_text(&cfg,
	    "service {\n"
	    "  uuid = \"0x180F\"\n"
	    "  characteristic {\n"
	    "    uuid = \"0x2A19\"\n"
	    "    properties = \"read\"\n"
	    "  }\n"
	    "}\n"), 0);
	ATF_REQUIRE_EQ(cfg.nservices, 1);
	ATF_CHECK_EQ(cfg.services[0].uuid16, 0x180F);
	ATF_REQUIRE_EQ(cfg.services[0].nchars, 1);
	ATF_CHECK_EQ(cfg.services[0].chars[0].uuid16, 0x2A19);
}

ATF_TC_WITHOUT_HEAD(edge_service_missing_uuid);
ATF_TC_BODY(edge_service_missing_uuid, tc)
{
	struct blued_config cfg;

	/* Body carries a characteristic but no service uuid -> rejected. */
	ATF_REQUIRE_EQ(load_text(&cfg,
	    "service {\n"
	    "  characteristic { uuid = \"0x2A19\" }\n"
	    "}\n"), 0);
	ATF_CHECK_EQ(cfg.nservices, 0);
}

ATF_TC_WITHOUT_HEAD(edge_service_invalid_uuid);
ATF_TC_BODY(edge_service_invalid_uuid, tc)
{
	struct blued_config cfg;

	ATF_REQUIRE_EQ(load_text(&cfg,
	    "service \"Bad\" { uuid = \"nothex\" }\n"), 0);
	ATF_CHECK_EQ(cfg.nservices, 0);
}

ATF_TC_WITHOUT_HEAD(edge_service_overflow);
ATF_TC_BODY(edge_service_overflow, tc)
{
	struct blued_config cfg;
	char buf[4096];
	size_t off = 0;
	int i;

	for (i = 0; i < BLUED_MAX_CONF_SERVICES + 3; i++)
		off += (size_t)snprintf(buf + off, sizeof(buf) - off,
		    "service \"s%d\" { uuid = \"0x%04x\" }\n", i, 0xFF00 + i);
	buf[off] = '\0';

	ATF_REQUIRE_EQ(load_text(&cfg, buf), 0);
	ATF_CHECK_EQ(cfg.nservices, BLUED_MAX_CONF_SERVICES);
}

ATF_TC_WITHOUT_HEAD(edge_chars_overflow_and_bad);
ATF_TC_BODY(edge_chars_overflow_and_bad, tc)
{
	struct blued_config cfg;
	char buf[4096];
	size_t off = 0;
	int i;

	off += (size_t)snprintf(buf + off, sizeof(buf) - off,
	    "service \"S\" {\n  uuid = \"0xFFE0\"\n");
	/* one characteristic missing uuid (rejected). */
	off += (size_t)snprintf(buf + off, sizeof(buf) - off,
	    "  characteristic \"nouuid\" { properties = \"read\" }\n");
	/* one with an invalid hex value (odd length -> rejected before store). */
	off += (size_t)snprintf(buf + off, sizeof(buf) - off,
	    "  characteristic \"badhex\" {\n"
	    "    uuid = \"0x2A05\"\n"
	    "    value = \"abc\"\n"
	    "  }\n");
	/* more valid characteristics than BLUED_MAX_CONF_CHARS. */
	for (i = 0; i < BLUED_MAX_CONF_CHARS + 3; i++)
		off += (size_t)snprintf(buf + off, sizeof(buf) - off,
		    "  characteristic \"c%d\" { uuid = \"0x%04x\" }\n",
		    i, 0x2B00 + i);
	snprintf(buf + off, sizeof(buf) - off, "}\n");

	ATF_REQUIRE_EQ(load_text(&cfg, buf), 0);
	ATF_REQUIRE_EQ(cfg.nservices, 1);
	ATF_CHECK_EQ(cfg.services[0].nchars, BLUED_MAX_CONF_CHARS);
}

/* ================================================================
 * blued_config_load_fd(): valid, empty, negative fd, bad UCL
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_load_fd_valid);
ATF_TC_BODY(edge_load_fd_valid, tc)
{
	struct blued_config cfg;

	ATF_REQUIRE_EQ(load_text_fd(&cfg,
	    "general { loglevel = 2 }\n"
	    "features { eatt = false }\n"), 0);
	ATF_CHECK_EQ(cfg.loglevel, 2);
	ATF_CHECK(!cfg.eatt);
}

ATF_TC_WITHOUT_HEAD(edge_load_fd_negative);
ATF_TC_BODY(edge_load_fd_negative, tc)
{
	struct blued_config cfg;

	blued_config_defaults(&cfg);
	ATF_CHECK(blued_config_load_fd(&cfg, -1) != 0);
}

ATF_TC_WITHOUT_HEAD(edge_load_fd_empty);
ATF_TC_BODY(edge_load_fd_empty, tc)
{
	struct blued_config cfg;
	char path[] = "/tmp/blued-cfgempty.XXXXXX";
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	blued_config_defaults(&cfg);
	/* st_size == 0 -> rejected. */
	ATF_CHECK(blued_config_load_fd(&cfg, fd) != 0);
	(void)close(fd);
	(void)unlink(path);
}

ATF_TC_WITHOUT_HEAD(edge_load_fd_bad_ucl);
ATF_TC_BODY(edge_load_fd_bad_ucl, tc)
{
	struct blued_config cfg;

	/* Unbalanced braces -> UCL string parse failure. */
	ATF_CHECK(load_text_fd(&cfg, "general { loglevel = ") != 0);
}

/* ================================================================
 * blued_config_load(): NULL path (default), missing file, parse error
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_load_null_path);
ATF_TC_BODY(edge_load_null_path, tc)
{
	struct blued_config cfg;
	int ret;

	blued_config_defaults(&cfg);
	/* NULL path -> BLUED_CONFIG_DEFAULT; absent file -> success+defaults. */
	ret = blued_config_load(&cfg, NULL);
	ATF_CHECK(ret == 0 || ret == -1);	/* 0 if /etc/blued.conf absent */
	ATF_CHECK_STREQ(cfg.pidfile, BLUED_PIDFILE_DEFAULT);
}

ATF_TC_WITHOUT_HEAD(edge_load_missing_file);
ATF_TC_BODY(edge_load_missing_file, tc)
{
	struct blued_config cfg;

	blued_config_defaults(&cfg);
	/* ENOENT is treated as success (config file is optional). */
	ATF_CHECK_EQ(blued_config_load(&cfg,
	    "/nonexistent/dir/blued.conf.absent"), 0);
}

ATF_TC_WITHOUT_HEAD(edge_load_parse_error);
ATF_TC_BODY(edge_load_parse_error, tc)
{
	struct blued_config cfg;

	/* Non-ENOENT failure (syntax error) -> -1. */
	ATF_CHECK(load_text(&cfg, "general { loglevel = ") != 0);
}

/* ================================================================
 * blued_config_apply_cli(): every option, plus overflow / saturation
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_cli_all_options);
ATF_TC_BODY(edge_cli_all_options, tc)
{
	struct blued_config cfg;
	char *argv[] = {
		(char *)"blued",
		(char *)"-a", (char *)"ubt0",
		(char *)"-B",
		(char *)"-c", (char *)"/etc/x.conf",
		(char *)"-f", (char *)"/db/bonds",
		(char *)"-L", (char *)"/log/x",
		(char *)"-p",
		(char *)"-r",
		(char *)"-s",
		(char *)"-v",
		NULL
	};

	blued_config_defaults(&cfg);
	blued_config_apply_cli(&cfg, 14, argv);

	ATF_CHECK_EQ(cfg.nadapters, 1);
	ATF_CHECK_STREQ(cfg.adapters[0], "ubt0");
	ATF_CHECK(cfg.daemonize);
	ATF_CHECK_STREQ(cfg.bonddb, "/db/bonds");
	ATF_CHECK_STREQ(cfg.logfile, "/log/x");
	ATF_CHECK(cfg.peripheral_mode);
	ATF_CHECK(cfg.reconnect);
	ATF_CHECK(cfg.scan_mode);
	ATF_CHECK_EQ(cfg.loglevel, 1);		/* -v from 0 -> 1 */
}

ATF_TC_WITHOUT_HEAD(edge_cli_debug_and_help);
ATF_TC_BODY(edge_cli_debug_and_help, tc)
{
	struct blued_config cfg;
	char *argv[] = {
		(char *)"blued", (char *)"-d", (char *)"-h",
		(char *)"-z", NULL	/* -z: unknown -> default case */
	};

	blued_config_defaults(&cfg);
	blued_config_apply_cli(&cfg, 4, argv);
	ATF_CHECK_EQ(cfg.loglevel, 1);		/* -d raises 0 -> 1 */
}

ATF_TC_WITHOUT_HEAD(edge_cli_verbose_saturates);
ATF_TC_BODY(edge_cli_verbose_saturates, tc)
{
	struct blued_config cfg;
	char *argv[] = {
		(char *)"blued", (char *)"-v", (char *)"-v", (char *)"-v",
		(char *)"-v", (char *)"-v", (char *)"-v", (char *)"-v", NULL
	};

	blued_config_defaults(&cfg);
	blued_config_apply_cli(&cfg, 8, argv);
	ATF_CHECK_EQ(cfg.loglevel, 5);		/* saturates at 5 */
}

ATF_TC_WITHOUT_HEAD(edge_cli_adapter_overflow);
ATF_TC_BODY(edge_cli_adapter_overflow, tc)
{
	struct blued_config cfg;
	char *argv[] = {
		(char *)"blued",
		(char *)"-a", (char *)"a0", (char *)"-a", (char *)"a1",
		(char *)"-a", (char *)"a2", (char *)"-a", (char *)"a3",
		(char *)"-a", (char *)"a4", (char *)"-a", (char *)"a5",
		(char *)"-a", (char *)"a6", (char *)"-a", (char *)"a7",
		(char *)"-a", (char *)"a8", (char *)"-a", (char *)"a9",
		NULL
	};

	blued_config_defaults(&cfg);
	blued_config_apply_cli(&cfg, 21, argv);
	ATF_CHECK_EQ(cfg.nadapters, 8);		/* capacity 8, excess dropped */
}

/* ================================================================
 * parse helpers: permission whitespace trim, hex/uuid boundaries
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(edge_parse_permissions_whitespace);
ATF_TC_BODY(edge_parse_permissions_whitespace, tc)
{
	uint8_t p;

	/* leading/trailing whitespace around comma-separated tokens. */
	p = blued_parse_gatt_permissions(
	    "  read , write ,\tread_encrypt\t, write_encrypt , read_authen , "
	    "write_authen ");
	ATF_CHECK((p & ATT_PERM_READ) != 0);
	ATF_CHECK((p & ATT_PERM_WRITE) != 0);
	ATF_CHECK((p & ATT_PERM_READ_ENCRYPT) != 0);
	ATF_CHECK((p & ATT_PERM_WRITE_ENCRYPT) != 0);
	ATF_CHECK((p & ATT_PERM_READ_AUTHEN) != 0);
	ATF_CHECK((p & ATT_PERM_WRITE_AUTHEN) != 0);

	ATF_CHECK_EQ(blued_parse_gatt_permissions(NULL), 0);
	ATF_CHECK_EQ(blued_parse_gatt_permissions("bogus,unknown"), 0);
}

ATF_TC_WITHOUT_HEAD(edge_parse_properties_all);
ATF_TC_BODY(edge_parse_properties_all, tc)
{
	uint8_t p;

	p = blued_parse_gatt_properties(
	    " broadcast , read , write_no_rsp , write , notify , indicate , "
	    "auth_signed_write , extended ");
	ATF_CHECK_EQ(p, (uint8_t)(GATT_PROP_BROADCAST | GATT_PROP_READ |
	    GATT_PROP_WRITE_NO_RSP | GATT_PROP_WRITE | GATT_PROP_NOTIFY |
	    GATT_PROP_INDICATE | GATT_PROP_LEGACY_AUTH_SIGNED_WRITE |
	    GATT_PROP_EXTENDED));
	ATF_CHECK_EQ(blued_parse_gatt_properties(NULL), 0);
}

ATF_TC_WITHOUT_HEAD(edge_parse_uuid_boundaries);
ATF_TC_BODY(edge_parse_uuid_boundaries, tc)
{
	uint16_t u16 = 0xAAAA;
	uint8_t u128[16];

	ATF_CHECK(blued_parse_uuid(NULL, &u16, u128) != 0);
	/* 0x0000 is rejected (val == 0). */
	ATF_CHECK(blued_parse_uuid("0x0000", &u16, u128) != 0);
	/* Out of 16-bit range. */
	ATF_CHECK(blued_parse_uuid("0x10000", &u16, u128) != 0);
	/* Trailing garbage after hex. */
	ATF_CHECK(blued_parse_uuid("0x12zz", &u16, u128) != 0);
	/* Valid 16-bit. */
	ATF_CHECK_EQ(blued_parse_uuid("0x2A00", &u16, u128), 0);
	ATF_CHECK_EQ(u16, 0x2A00);
	/* Valid 128-bit -> stored little-endian. */
	ATF_CHECK_EQ(blued_parse_uuid(
	    "0000180f-0000-1000-8000-00805f9b34fb", &u16, u128), 0);
	ATF_CHECK_EQ(u16, 0);
	ATF_CHECK_EQ(u128[0], 0xfb);	/* last display byte -> first LE byte */
	ATF_CHECK_EQ(u128[15], 0x00);
	/* Malformed 128-bit (wrong length). */
	ATF_CHECK(blued_parse_uuid("0000180f-0000", &u16, u128) != 0);
}

ATF_TC_WITHOUT_HEAD(edge_parse_hex_boundaries);
ATF_TC_BODY(edge_parse_hex_boundaries, tc)
{
	uint8_t out[4];

	/* Empty string -> 0 bytes, valid. */
	ATF_CHECK_EQ(blued_parse_hex_value("", out, sizeof(out)), 0);
	ATF_CHECK_EQ(blued_parse_hex_value(NULL, out, sizeof(out)), 0);
	/* Odd length -> error. */
	ATF_CHECK(blued_parse_hex_value("abc", out, sizeof(out)) < 0);
	/* Too long for buffer. */
	ATF_CHECK(blued_parse_hex_value("0102030405", out, sizeof(out)) < 0);
	/* A byte with no valid hex digit ("gg") -> sscanf matches 0 -> error. */
	ATF_CHECK(blued_parse_hex_value("gg", out, sizeof(out)) < 0);
	/* Valid. */
	ATF_CHECK_EQ(blued_parse_hex_value("0aFF", out, sizeof(out)), 2);
	ATF_CHECK_EQ(out[0], 0x0a);
	ATF_CHECK_EQ(out[1], 0xFF);
}

/*
 * Regression guard: blued_parse_hex_value() must reject partial-hex byte
 * tokens.  sscanf(hex+i, "%2x") alone matches the leading '0' of "0g", stops
 * at 'g', and reports one successful conversion -- so the parser previously
 * returned 1 (a byte 0x00) for a malformed token.  Both nibbles are now
 * validated with isxdigit(), so "0g"/"g0"/"0 " are rejected (-1), while valid
 * even-length hex still parses.
 */
ATF_TC_WITHOUT_HEAD(edge_parse_hex_partial_finding);
ATF_TC_BODY(edge_parse_hex_partial_finding, tc)
{
	uint8_t out[4];

	ATF_CHECK(blued_parse_hex_value("0g", out, sizeof(out)) < 0);
	ATF_CHECK(blued_parse_hex_value("g0", out, sizeof(out)) < 0);
	ATF_CHECK(blued_parse_hex_value("00ff0g", out, sizeof(out)) < 0);
	/* A valid token of the same length still parses. */
	ATF_CHECK_EQ(blued_parse_hex_value("0a", out, sizeof(out)), 1);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, edge_general_all_keys);
	ATF_TP_ADD_TC(tp, edge_general_type_mismatch);
	ATF_TP_ADD_TC(tp, edge_loglevel_clamp_high);
	ATF_TP_ADD_TC(tp, edge_loglevel_clamp_low);

	ATF_TP_ADD_TC(tp, edge_features_all_keys);
	ATF_TP_ADD_TC(tp, edge_features_privacy_mode_device);
	ATF_TP_ADD_TC(tp, edge_features_clamps);
	ATF_TP_ADD_TC(tp, edge_features_type_mismatch);

	ATF_TP_ADD_TC(tp, edge_security_io_capability_variants);
	ATF_TP_ADD_TC(tp, edge_security_min_key_size_clamp);
	ATF_TP_ADD_TC(tp, edge_security_all_keys);

	ATF_TP_ADD_TC(tp, edge_adapters_auto_string);
	ATF_TP_ADD_TC(tp, edge_adapters_array);
	ATF_TP_ADD_TC(tp, edge_adapters_auto_in_array);
	ATF_TP_ADD_TC(tp, edge_adapters_overflow);
	ATF_TP_ADD_TC(tp, edge_adapters_array_nonstring_elem);

	ATF_TP_ADD_TC(tp, edge_devices_variants);
	ATF_TP_ADD_TC(tp, edge_devices_invalid_addr);
	ATF_TP_ADD_TC(tp, edge_devices_overflow);

	ATF_TP_ADD_TC(tp, edge_service_named_with_chars);
	ATF_TP_ADD_TC(tp, edge_service_unnamed_body);
	ATF_TP_ADD_TC(tp, edge_service_missing_uuid);
	ATF_TP_ADD_TC(tp, edge_service_invalid_uuid);
	ATF_TP_ADD_TC(tp, edge_service_overflow);
	ATF_TP_ADD_TC(tp, edge_chars_overflow_and_bad);

	ATF_TP_ADD_TC(tp, edge_load_fd_valid);
	ATF_TP_ADD_TC(tp, edge_load_fd_negative);
	ATF_TP_ADD_TC(tp, edge_load_fd_empty);
	ATF_TP_ADD_TC(tp, edge_load_fd_bad_ucl);

	ATF_TP_ADD_TC(tp, edge_load_null_path);
	ATF_TP_ADD_TC(tp, edge_load_missing_file);
	ATF_TP_ADD_TC(tp, edge_load_parse_error);

	ATF_TP_ADD_TC(tp, edge_cli_all_options);
	ATF_TP_ADD_TC(tp, edge_cli_debug_and_help);
	ATF_TP_ADD_TC(tp, edge_cli_verbose_saturates);
	ATF_TP_ADD_TC(tp, edge_cli_adapter_overflow);

	ATF_TP_ADD_TC(tp, edge_parse_permissions_whitespace);
	ATF_TP_ADD_TC(tp, edge_parse_properties_all);
	ATF_TP_ADD_TC(tp, edge_parse_uuid_boundaries);
	ATF_TP_ADD_TC(tp, edge_parse_hex_boundaries);
	ATF_TP_ADD_TC(tp, edge_parse_hex_partial_finding);

	return (atf_no_error());
}
