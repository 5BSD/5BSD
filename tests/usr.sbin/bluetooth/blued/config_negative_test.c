/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF negative/adversarial tests for the blued UCL configuration parser
 * (config.c).
 *
 * The config file is untrusted local input (an admin edit, or a file an
 * attacker who can write /etc/blued.conf controls).  These tests feed
 * malformed and adversarial configs and assert the parser either rejects
 * them or falls back to safe defaults, always leaving the config struct
 * in a sane, in-bounds state, and never crashing.
 *
 * Coverage:
 *   - syntax errors and non-UCL garbage;
 *   - wrong value types for typed options (string where int expected, …);
 *   - out-of-range numerics clamped: rpa_timeout,
 *     min_key_size, reconnect_max_delay (negative and huge);
 *   - missing fields / empty file -> defaults;
 *   - fixed-array overflow: >16 devices, >8 services, >8 adapters;
 *   - very large and deeply nested input;
 *   - injection via string values (control chars, separators, overlong);
 *   - the blued_config_load_fd() SIGHUP-reload entry point (empty,
 *     negative fd, valid).
 *
 * Every config is written to a UNIQUE temp file via mkstemp(3) and
 * unlinked after use — nothing is written into the current directory.
 * Links config.c with LIBADD ucl, mirroring config_test.c.
 */

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

/*
 * Write text to a unique temp file (mkstemp), load it into a
 * defaults-initialized cfg, unlink the file, and return the load result.
 */
static int
load_text(struct blued_config *cfg, const char *text)
{
	char path[] = "/tmp/blued-cfgneg.XXXXXX";
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

/* Assert the fixed-path string fields are always NUL-terminated & in-bounds. */
static void
check_sane(const struct blued_config *cfg)
{

	ATF_CHECK(strnlen(cfg->pidfile, sizeof(cfg->pidfile)) <
	    sizeof(cfg->pidfile));
	ATF_CHECK(strnlen(cfg->bonddb, sizeof(cfg->bonddb)) <
	    sizeof(cfg->bonddb));
	ATF_CHECK(strnlen(cfg->ctlsock, sizeof(cfg->ctlsock)) <
	    sizeof(cfg->ctlsock));
	ATF_CHECK(strnlen(cfg->logfile, sizeof(cfg->logfile)) <
	    sizeof(cfg->logfile));
	ATF_CHECK(strnlen(cfg->peripheral_name, sizeof(cfg->peripheral_name)) <
	    sizeof(cfg->peripheral_name));
	ATF_CHECK(cfg->ndevices >= 0 && cfg->ndevices <= BLUED_MAX_DEVICES);
	ATF_CHECK(cfg->nservices >= 0 &&
	    cfg->nservices <= BLUED_MAX_CONF_SERVICES);
	ATF_CHECK(cfg->nadapters >= 0 &&
	    cfg->nadapters <= (int)(sizeof(cfg->adapters) /
	    sizeof(cfg->adapters[0])));
	ATF_CHECK(cfg->min_key_size >= 7 && cfg->min_key_size <= 16);
	ATF_CHECK(cfg->rpa_timeout >= 1 && cfg->rpa_timeout <= 3600);
	ATF_CHECK(cfg->reconnect_max_delay >= 1 &&
	    cfg->reconnect_max_delay <= 3600);
}

/* ================================================================
 * Syntax errors / non-UCL garbage
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_cfgn_unbalanced_brace);
ATF_TC_BODY(test_cfgn_unbalanced_brace, tc)
{
	struct blued_config cfg;

	/* Missing closing brace */
	(void)load_text(&cfg,
	    "general {\n"
	    "  loglevel = 3;\n"
	    "  bonddb = \"/tmp/x\";\n");
	/* Either rejected (-1) or defaults kept — struct must be sane. */
	check_sane(&cfg);
}

ATF_TC_WITHOUT_HEAD(test_cfgn_garbage_bytes);
ATF_TC_BODY(test_cfgn_garbage_bytes, tc)
{
	struct blued_config cfg;

	(void)load_text(&cfg,
	    "\x01\x02 not = = = valid {{{ ][ ;;; \xff\xfe garbage\n");
	check_sane(&cfg);

	(void)load_text(&cfg, "}}}}}}}}}}\n");
	check_sane(&cfg);
}

/* ================================================================
 * Wrong value types — typed options must be ignored, defaults kept
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_cfgn_wrong_types);
ATF_TC_BODY(test_cfgn_wrong_types, tc)
{
	struct blued_config cfg;
	int ret;

	ret = load_text(&cfg,
	    "general {\n"
	    "  loglevel = \"high\";\n"		/* string, not int */
	    "  daemonize = 7;\n"		/* int, not bool */
	    "}\n"
	    "features {\n"
	    "  eatt = \"maybe\";\n"		/* string, not bool */
	    "  rpa_timeout = \"soon\";\n"	/* string, not int */
	    "}\n"
	    "security {\n"
	    "  min_key_size = \"big\";\n"	/* string, not int */
	    "  bondable = 3;\n"			/* int, not bool */
	    "}\n");

	ATF_CHECK_EQ(ret, 0);
	/* All wrong-typed options ignored -> defaults preserved */
	ATF_CHECK_EQ(cfg.loglevel, 0);
	ATF_CHECK(cfg.eatt);
	ATF_CHECK_EQ(cfg.rpa_timeout, BLUED_RPA_TIMEOUT_DEFAULT);
	ATF_CHECK_EQ(cfg.min_key_size, BLUED_MIN_KEY_SIZE_DEFAULT);
	ATF_CHECK(cfg.bondable);
	check_sane(&cfg);
}

ATF_TC_WITHOUT_HEAD(test_cfgn_wrong_section_types);
ATF_TC_BODY(test_cfgn_wrong_section_types, tc)
{
	struct blued_config cfg;

	/* Sections given non-object values — must be ignored */
	(void)load_text(&cfg,
	    "general = \"nope\";\n"
	    "features = 42;\n"
	    "security = true;\n"
	    "devices = \"none\";\n");
	check_sane(&cfg);
}

/* ================================================================
 * Out-of-range numerics — clamped both directions
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_cfgn_numeric_clamp_negative);
ATF_TC_BODY(test_cfgn_numeric_clamp_negative, tc)
{
	struct blued_config cfg;

	ATF_CHECK_EQ(load_text(&cfg,
	    "features {\n"
	    "  rpa_timeout = -100;\n"
	    "  reconnect_max_delay = -1;\n"
	    "}\n"
	    "security {\n"
	    "  min_key_size = -8;\n"
	    "}\n"), 0);

	ATF_CHECK_EQ(cfg.rpa_timeout, 1);
	ATF_CHECK_EQ(cfg.reconnect_max_delay, 1);
	ATF_CHECK_EQ(cfg.min_key_size, 7);
	check_sane(&cfg);
}

ATF_TC_WITHOUT_HEAD(test_cfgn_numeric_clamp_huge);
ATF_TC_BODY(test_cfgn_numeric_clamp_huge, tc)
{
	struct blued_config cfg;

	ATF_CHECK_EQ(load_text(&cfg,
	    "features {\n"
	    "  rpa_timeout = 999999999;\n"
	    "  reconnect_max_delay = 88888888;\n"
	    "}\n"
	    "security {\n"
	    "  min_key_size = 4096;\n"
	    "}\n"), 0);

	ATF_CHECK_EQ(cfg.rpa_timeout, 3600);
	ATF_CHECK_EQ(cfg.reconnect_max_delay, 3600);
	ATF_CHECK_EQ(cfg.min_key_size, 16);
	check_sane(&cfg);
}

ATF_TC_WITHOUT_HEAD(test_cfgn_loglevel_clamp);
ATF_TC_BODY(test_cfgn_loglevel_clamp, tc)
{
	struct blued_config cfg;

	ATF_CHECK_EQ(load_text(&cfg, "general { loglevel = 999; }\n"), 0);
	ATF_CHECK_EQ(cfg.loglevel, 5);

	ATF_CHECK_EQ(load_text(&cfg, "general { loglevel = -20; }\n"), 0);
	ATF_CHECK_EQ(cfg.loglevel, 0);
	check_sane(&cfg);
}

/* ================================================================
 * Missing fields / empty file -> defaults
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_cfgn_empty_file);
ATF_TC_BODY(test_cfgn_empty_file, tc)
{
	struct blued_config cfg;

	ATF_CHECK_EQ(load_text(&cfg, ""), 0);
	ATF_CHECK_STREQ(cfg.pidfile, BLUED_PIDFILE_DEFAULT);
	ATF_CHECK_STREQ(cfg.bonddb, BLUED_BONDDB_DEFAULT);
	ATF_CHECK_STREQ(cfg.ctlsock, BLUED_CTLSOCK_DEFAULT);
	ATF_CHECK_EQ(cfg.ndevices, 0);
	ATF_CHECK_EQ(cfg.nservices, 0);
	check_sane(&cfg);

	/* whitespace-only and comment-only files */
	ATF_CHECK_EQ(load_text(&cfg, "   \n\t\n"), 0);
	check_sane(&cfg);
	ATF_CHECK_EQ(load_text(&cfg, "# just a comment\n"), 0);
	check_sane(&cfg);
}

ATF_TC_WITHOUT_HEAD(test_cfgn_partial_sections);
ATF_TC_BODY(test_cfgn_partial_sections, tc)
{
	struct blued_config cfg;

	/* Empty sections must not disturb defaults */
	ATF_CHECK_EQ(load_text(&cfg,
	    "general {}\n"
	    "features {}\n"
	    "security {}\n"
	    "devices {}\n"), 0);
	ATF_CHECK_EQ(cfg.loglevel, 0);
	ATF_CHECK_EQ(cfg.ndevices, 0);
	check_sane(&cfg);
}

/* ================================================================
 * Fixed-array overflow: more entries than the arrays can hold
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_cfgn_devices_overflow);
ATF_TC_BODY(test_cfgn_devices_overflow, tc)
{
	struct blued_config cfg;
	char buf[4096];
	size_t off;
	int i, ret;

	off = 0;
	off += (size_t)snprintf(buf + off, sizeof(buf) - off, "devices {\n");
	/* 40 distinct valid addresses — more than BLUED_MAX_DEVICES (16) */
	for (i = 1; i <= 40; i++)
		off += (size_t)snprintf(buf + off, sizeof(buf) - off,
		    "  \"00:00:00:00:00:%02X\" { type = \"random\"; }\n", i);
	(void)snprintf(buf + off, sizeof(buf) - off, "}\n");

	ret = load_text(&cfg, buf);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_MSG(cfg.ndevices <= BLUED_MAX_DEVICES,
	    "ndevices=%d exceeds max %d", cfg.ndevices, BLUED_MAX_DEVICES);
	check_sane(&cfg);
}

ATF_TC_WITHOUT_HEAD(test_cfgn_services_overflow);
ATF_TC_BODY(test_cfgn_services_overflow, tc)
{
	struct blued_config cfg;
	char buf[4096];
	size_t off;
	int i, ret;

	off = 0;
	off += (size_t)snprintf(buf + off, sizeof(buf) - off, "service {\n");
	/* 20 named services — more than BLUED_MAX_CONF_SERVICES (8) */
	for (i = 1; i <= 20; i++)
		off += (size_t)snprintf(buf + off, sizeof(buf) - off,
		    "  \"svc%d\" { uuid = \"0x%04X\"; }\n", i, 0xFF00 + i);
	(void)snprintf(buf + off, sizeof(buf) - off, "}\n");

	ret = load_text(&cfg, buf);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_MSG(cfg.nservices <= BLUED_MAX_CONF_SERVICES,
	    "nservices=%d exceeds max %d", cfg.nservices,
	    BLUED_MAX_CONF_SERVICES);
	check_sane(&cfg);
}

ATF_TC_WITHOUT_HEAD(test_cfgn_adapters_overflow);
ATF_TC_BODY(test_cfgn_adapters_overflow, tc)
{
	struct blued_config cfg;
	char buf[2048];
	size_t off;
	int i, ret, maxa;

	maxa = (int)(sizeof(cfg.adapters) / sizeof(cfg.adapters[0]));

	off = 0;
	off += (size_t)snprintf(buf + off, sizeof(buf) - off, "adapters = [");
	for (i = 0; i < 100; i++)
		off += (size_t)snprintf(buf + off, sizeof(buf) - off,
		    "%s\"ubt%d\"", i > 0 ? ", " : "", i);
	(void)snprintf(buf + off, sizeof(buf) - off, "];\n");

	ret = load_text(&cfg, buf);
	ATF_CHECK_EQ(ret, 0);
	ATF_CHECK_MSG(cfg.nadapters <= maxa,
	    "nadapters=%d exceeds max %d", cfg.nadapters, maxa);
	check_sane(&cfg);
}

ATF_TC_WITHOUT_HEAD(test_cfgn_chars_overflow);
ATF_TC_BODY(test_cfgn_chars_overflow, tc)
{
	struct blued_config cfg;
	char buf[4096];
	size_t off;
	int i, ret;

	off = 0;
	off += (size_t)snprintf(buf + off, sizeof(buf) - off,
	    "service {\n  uuid = \"0xFFE0\";\n  characteristic {\n");
	/* Many characteristics under one service — capped at
	 * BLUED_MAX_CONF_CHARS (8) */
	for (i = 1; i <= 20; i++)
		off += (size_t)snprintf(buf + off, sizeof(buf) - off,
		    "    \"c%d\" { uuid = \"0x%04X\"; properties = \"read\"; }\n",
		    i, 0xFE00 + i);
	(void)snprintf(buf + off, sizeof(buf) - off, "  }\n}\n");

	ret = load_text(&cfg, buf);
	ATF_CHECK_EQ(ret, 0);
	if (cfg.nservices > 0)
		ATF_CHECK_MSG(cfg.services[0].nchars <= BLUED_MAX_CONF_CHARS,
		    "nchars=%d exceeds max %d", cfg.services[0].nchars,
		    BLUED_MAX_CONF_CHARS);
	check_sane(&cfg);
}

/* ================================================================
 * Bad addresses / bad hex values inside otherwise valid structures
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_cfgn_bad_device_addr);
ATF_TC_BODY(test_cfgn_bad_device_addr, tc)
{
	struct blued_config cfg;

	/* Invalid address keys must be skipped, not stored */
	ATF_CHECK_EQ(load_text(&cfg,
	    "devices {\n"
	    "  \"not-an-address\" { type = \"random\"; }\n"
	    "  \"zz:zz:zz:zz:zz:zz\" { }\n"
	    "  \"aa:bb:cc:dd:ee:ff\" { type = \"public\"; }\n"
	    "}\n"), 0);
	/* Only the one valid address counts */
	ATF_CHECK_EQ(cfg.ndevices, 1);
	check_sane(&cfg);
}

ATF_TC_WITHOUT_HEAD(test_cfgn_bad_char_value);
ATF_TC_BODY(test_cfgn_bad_char_value, tc)
{
	struct blued_config cfg;

	/* Odd-length / non-hex value must cause the char to be skipped */
	ATF_CHECK_EQ(load_text(&cfg,
	    "service {\n"
	    "  uuid = \"0xFFE0\";\n"
	    "  characteristic {\n"
	    "    uuid = \"0xFFE1\";\n"
	    "    properties = \"read\";\n"
	    "    value = \"ABC\";\n"		/* odd length */
	    "  }\n"
	    "}\n"), 0);
	ATF_CHECK_EQ(cfg.nservices, 1);
	if (cfg.nservices > 0)
		ATF_CHECK_EQ(cfg.services[0].nchars, 0);
	check_sane(&cfg);
}

ATF_TC_WITHOUT_HEAD(test_cfgn_bad_service_uuid);
ATF_TC_BODY(test_cfgn_bad_service_uuid, tc)
{
	struct blued_config cfg;

	/* Service with an invalid uuid must be skipped */
	ATF_CHECK_EQ(load_text(&cfg,
	    "service {\n"
	    "  uuid = \"not-a-uuid\";\n"
	    "}\n"), 0);
	ATF_CHECK_EQ(cfg.nservices, 0);

	/* Missing uuid entirely */
	ATF_CHECK_EQ(load_text(&cfg,
	    "service {\n"
	    "  characteristic { uuid = \"0xFFE1\"; }\n"
	    "}\n"), 0);
	ATF_CHECK_EQ(cfg.nservices, 0);
	check_sane(&cfg);
}

/* ================================================================
 * Injection via string values / overlong strings
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_cfgn_string_injection);
ATF_TC_BODY(test_cfgn_string_injection, tc)
{
	struct blued_config cfg;

	/* Separators, spaces, shell metachars in a path string — copied
	 * verbatim by strlcpy, no interpretation, no crash. */
	ATF_CHECK_EQ(load_text(&cfg,
	    "general {\n"
	    "  pidfile = \"/tmp/a; rm -rf / | nc evil 9\";\n"
	    "  peripheral_name = \"pwn$(id)\\ttab\";\n"
	    "}\n"), 0);
	ATF_CHECK(strstr(cfg.pidfile, "rm -rf") != NULL);
	check_sane(&cfg);
}

ATF_TC_WITHOUT_HEAD(test_cfgn_overlong_string);
ATF_TC_BODY(test_cfgn_overlong_string, tc)
{
	struct blued_config cfg;
	char *buf;
	size_t i, off, n = 9000;

	/* pidfile value far longer than PATH_MAX must be truncated safely */
	buf = malloc(n + 64);
	ATF_REQUIRE(buf != NULL);
	off = (size_t)snprintf(buf, n + 64, "general {\n  pidfile = \"");
	for (i = 0; i < n; i++)
		buf[off++] = 'x';
	(void)snprintf(buf + off, n + 64 - off, "\";\n}\n");

	ATF_CHECK_EQ(load_text(&cfg, buf), 0);
	check_sane(&cfg);		/* strnlen bounds verified inside */

	free(buf);
}

/* ================================================================
 * Very large / deeply nested input
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_cfgn_large_input);
ATF_TC_BODY(test_cfgn_large_input, tc)
{
	struct blued_config cfg;
	char *buf;
	size_t off, cap = 200000;
	int i;

	buf = malloc(cap);
	ATF_REQUIRE(buf != NULL);

	/* A big pile of unknown keys plus a huge comment block. */
	off = (size_t)snprintf(buf, cap, "general { loglevel = 2; }\n");
	for (i = 0; i < 5000 && off < cap - 64; i++)
		off += (size_t)snprintf(buf + off, cap - off,
		    "unknown_key_%d = \"value_%d\";\n", i, i);
	buf[off] = '\0';

	ATF_CHECK_EQ(load_text(&cfg, buf), 0);
	ATF_CHECK_EQ(cfg.loglevel, 2);
	check_sane(&cfg);

	free(buf);
}

ATF_TC_WITHOUT_HEAD(test_cfgn_deep_nesting);
ATF_TC_BODY(test_cfgn_deep_nesting, tc)
{
	struct blued_config cfg;
	char *buf;
	size_t off, cap = 8192;
	int i, depth = 200;

	buf = malloc(cap);
	ATF_REQUIRE(buf != NULL);

	/* Deeply nested objects under an unknown key.  The parser may
	 * reject this (recursion limit) or accept it — either way it must
	 * not crash and cfg must stay sane. */
	off = 0;
	for (i = 0; i < depth && off < cap - 8; i++)
		off += (size_t)snprintf(buf + off, cap - off, "k { ");
	for (i = 0; i < depth && off < cap - 4; i++)
		off += (size_t)snprintf(buf + off, cap - off, "} ");
	buf[off] = '\0';

	(void)load_text(&cfg, buf);
	check_sane(&cfg);

	free(buf);
}

/* ================================================================
 * blued_config_load_fd — the SIGHUP-reload entry point
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(test_cfgn_load_fd_valid);
ATF_TC_BODY(test_cfgn_load_fd_valid, tc)
{
	struct blued_config cfg;
	char path[] = "/tmp/blued-cfgfd.XXXXXX";
	const char *text =
	    "general { loglevel = 4; }\n"
	    "features { privacy = false; }\n";
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(write(fd, text, strlen(text)) == (ssize_t)strlen(text));

	blued_config_defaults(&cfg);
	ATF_CHECK_EQ(blued_config_load_fd(&cfg, fd), 0);
	ATF_CHECK_EQ(cfg.loglevel, 4);
	ATF_CHECK(!cfg.privacy);
	check_sane(&cfg);

	close(fd);
	(void)unlink(path);
}

ATF_TC_WITHOUT_HEAD(test_cfgn_load_fd_empty);
ATF_TC_BODY(test_cfgn_load_fd_empty, tc)
{
	struct blued_config cfg;
	char path[] = "/tmp/blued-cfgfd.XXXXXX";
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);

	/* Empty file: st_size <= 0 must be rejected, defaults intact */
	blued_config_defaults(&cfg);
	ATF_CHECK_EQ(blued_config_load_fd(&cfg, fd), -1);
	check_sane(&cfg);

	close(fd);
	(void)unlink(path);
}

ATF_TC_WITHOUT_HEAD(test_cfgn_load_fd_negative);
ATF_TC_BODY(test_cfgn_load_fd_negative, tc)
{
	struct blued_config cfg;

	blued_config_defaults(&cfg);
	ATF_CHECK_EQ(blued_config_load_fd(&cfg, -1), -1);
	check_sane(&cfg);
}

ATF_TC_WITHOUT_HEAD(test_cfgn_load_fd_garbage);
ATF_TC_BODY(test_cfgn_load_fd_garbage, tc)
{
	struct blued_config cfg;
	char path[] = "/tmp/blued-cfgfd.XXXXXX";
	const char *text = "this is not { valid ][ ucl ;;;\n";
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(write(fd, text, strlen(text)) == (ssize_t)strlen(text));

	blued_config_defaults(&cfg);
	/* Parse error -> -1; either way defaults must remain sane */
	(void)blued_config_load_fd(&cfg, fd);
	check_sane(&cfg);

	close(fd);
	(void)unlink(path);
}

/* ================================================================
 * ATF test program entry point
 * ================================================================ */
ATF_TP_ADD_TCS(tp)
{

	/* Syntax / garbage */
	ATF_TP_ADD_TC(tp, test_cfgn_unbalanced_brace);
	ATF_TP_ADD_TC(tp, test_cfgn_garbage_bytes);

	/* Wrong types */
	ATF_TP_ADD_TC(tp, test_cfgn_wrong_types);
	ATF_TP_ADD_TC(tp, test_cfgn_wrong_section_types);

	/* Numeric clamping */
	ATF_TP_ADD_TC(tp, test_cfgn_numeric_clamp_negative);
	ATF_TP_ADD_TC(tp, test_cfgn_numeric_clamp_huge);
	ATF_TP_ADD_TC(tp, test_cfgn_loglevel_clamp);

	/* Missing fields */
	ATF_TP_ADD_TC(tp, test_cfgn_empty_file);
	ATF_TP_ADD_TC(tp, test_cfgn_partial_sections);

	/* Array overflow */
	ATF_TP_ADD_TC(tp, test_cfgn_devices_overflow);
	ATF_TP_ADD_TC(tp, test_cfgn_services_overflow);
	ATF_TP_ADD_TC(tp, test_cfgn_adapters_overflow);
	ATF_TP_ADD_TC(tp, test_cfgn_chars_overflow);

	/* Bad values inside valid structures */
	ATF_TP_ADD_TC(tp, test_cfgn_bad_device_addr);
	ATF_TP_ADD_TC(tp, test_cfgn_bad_char_value);
	ATF_TP_ADD_TC(tp, test_cfgn_bad_service_uuid);

	/* Injection / overlong strings */
	ATF_TP_ADD_TC(tp, test_cfgn_string_injection);
	ATF_TP_ADD_TC(tp, test_cfgn_overlong_string);

	/* Large / deeply nested */
	ATF_TP_ADD_TC(tp, test_cfgn_large_input);
	ATF_TP_ADD_TC(tp, test_cfgn_deep_nesting);

	/* load_fd entry point */
	ATF_TP_ADD_TC(tp, test_cfgn_load_fd_valid);
	ATF_TP_ADD_TC(tp, test_cfgn_load_fd_empty);
	ATF_TP_ADD_TC(tp, test_cfgn_load_fd_negative);
	ATF_TP_ADD_TC(tp, test_cfgn_load_fd_garbage);

	return (atf_no_error());
}
