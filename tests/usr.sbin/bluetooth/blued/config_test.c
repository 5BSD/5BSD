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

#include <atf-c.h>
#include <stdio.h>
#include <string.h>

#include "config.h"
#include "smp.h"

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

	blued_config_defaults(&cfg);
	ATF_REQUIRE_EQ(blued_config_load(&cfg, "missing.conf"), 0);

	ATF_CHECK_STREQ(cfg.pidfile, "/var/run/blued.pid");
	ATF_CHECK_STREQ(cfg.bonddb, "/var/db/blued/bonds");
	ATF_CHECK_STREQ(cfg.ctlsock, "/var/run/blued.sock");
	ATF_CHECK_EQ(cfg.loglevel, 0);
	ATF_CHECK_EQ(cfg.nadapters, 0);
	ATF_CHECK_EQ(cfg.io_capability, SMP_IO_KEYBOARD_DISPLAY);
	ATF_CHECK(cfg.bondable);
	ATF_CHECK(!cfg.sc_only);
	ATF_CHECK(cfg.eatt);
	ATF_CHECK(cfg.privacy);
	ATF_CHECK(cfg.reconnect);
	ATF_CHECK_EQ(cfg.reconnect_max_delay, 60);
}

ATF_TC_WITHOUT_HEAD(parses_nested_sample_shape);
ATF_TC_BODY(parses_nested_sample_shape, tc)
{
	struct blued_config cfg;
	const char *path = "nested.conf";

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
	    "  sc_only = true;\n"
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
	ATF_CHECK(cfg.sc_only);
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
	const char *path = "auto-adapter.conf";

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
	const char *path = "legacy-top-level.conf";

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
	ATF_CHECK_EQ(cfg.ndevices, 0);
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
	const char *path = "min_key_size.conf";

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
	const char *path = "svc128.conf";

	write_config(path,
	    "service {\n"
	    "  uuid = \"12345678-1234-5678-9abc-def012345678\";\n"
	    "}\n");
	blued_config_defaults(&cfg);
	ATF_REQUIRE_EQ(blued_config_load(&cfg, path), 0);
	ATF_CHECK_EQ(cfg.nservices, 1);
	ATF_CHECK_EQ(cfg.services[0].uuid16, 0);
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

	/* Odd-length hex should fail */
	ret = blued_parse_hex_value("012", buf, sizeof(buf));
	ATF_CHECK(ret <= 0);

	/* Empty string */
	ret = blued_parse_hex_value("", buf, sizeof(buf));
	ATF_CHECK_EQ(ret, 0);

	/* NULL string */
	ret = blued_parse_hex_value(NULL, buf, sizeof(buf));
	ATF_CHECK(ret <= 0);
}

/* ================================================================
 * Test: malformed UCL (truncated, missing closing brace).
 * blued_config_load should return error or use defaults gracefully.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_config_malformed_ucl);
ATF_TC_BODY(test_config_malformed_ucl, tc)
{
	struct blued_config cfg;
	const char *path = "malformed.conf";
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
	 * The config parser should either return an error (non-zero)
	 * or gracefully use defaults.  Either way, check that the
	 * config struct is in a sane state and the caller doesn't crash.
	 */
	if (ret == 0) {
		/* Parser was lenient — verify defaults are still sane */
		ATF_CHECK(cfg.pidfile[0] != '\0');
		ATF_CHECK(cfg.bonddb[0] != '\0');
		ATF_CHECK(cfg.ctlsock[0] != '\0');
	}
	/* If ret != 0, that's also acceptable — it detected the error */
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, defaults_for_missing_config);
	ATF_TP_ADD_TC(tp, parses_nested_sample_shape);
	ATF_TP_ADD_TC(tp, parses_auto_adapter);
	ATF_TP_ADD_TC(tp, ignores_top_level_legacy_shape);
	ATF_TP_ADD_TC(tp, cli_overrides_config);
	ATF_TP_ADD_TC(tp, test_config_min_key_size);
	ATF_TP_ADD_TC(tp, test_config_service_uuid128);
	ATF_TP_ADD_TC(tp, test_config_hex_value_odd_length);
	ATF_TP_ADD_TC(tp, test_config_malformed_ucl);

	return (atf_no_error());
}
