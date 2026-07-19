/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATF spec-oracle unit tests for hccontrol/util.c HCI decode helpers.
 *
 * Oracle: Bluetooth Core Specification 6.3.
 *   - Error codes (hci_status2str):       Vol 1 Part F, "List of Error Codes".
 *   - Supported_Commands (hci_commands2str): Vol 4 Part E 6.27 / 7.4.2.
 *   - LE channel map (hci_le_chanmap2str):   Vol 4 Part E 7.8.20 (5 octets,
 *     one bit per data channel, LSB of octet 0 == channel 0).
 *
 * These helpers are pure (no I/O to a controller), so they are exercised
 * directly.  stdout is redirected to a tmpfile so tests can also assert that
 * a decode helper writes nothing to stdout (a formatter must return a string,
 * not print).
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>

#include "hccontrol.h"

/* util.c: hci_bdaddr2str() references this hccontrol global; stub it. */
extern int	numeric_bdaddr;
int	numeric_bdaddr = 0;

/* ---- stdout capture ------------------------------------------------ */
struct capture {
	FILE	*saved;
	FILE	*tmp;
	char	 buf[8192];
};

static void
capture_begin(struct capture *c)
{
	fflush(stdout);
	c->saved = stdout;
	c->tmp = tmpfile();
	ATF_REQUIRE(c->tmp != NULL);
	stdout = c->tmp;
}

static void
capture_end(struct capture *c)
{
	long	n;

	fflush(stdout);
	stdout = c->saved;
	rewind(c->tmp);
	n = fread(c->buf, 1, sizeof(c->buf) - 1, c->tmp);
	if (n < 0)
		n = 0;
	c->buf[n] = '\0';
	fclose(c->tmp);
}

/* ================================================================
 * hci_status2str: Core 6.3 Vol 1 Part F error-code strings.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(status_error_strings);
ATF_TC_BODY(status_error_strings, tc)
{
	/* Spot-check unambiguous, stable entries. */
	ATF_CHECK_STREQ("No error", hci_status2str(0x00));
	ATF_CHECK_STREQ("Command disallowed", hci_status2str(0x0c));

	/*
	 * Regression: 0x0F, 0x24 and 0x26 previously carried legacy
	 * Bluetooth-1.1 wording that named the WRONG condition.
	 * Core 6.3 Vol 1 Part F:
	 *   0x0F = "Rejected due to Unacceptable BD_ADDR"
	 *   0x24 = "LMP PDU Not Allowed"
	 *   0x26 = "Link Key cannot be Changed"
	 */
	ATF_CHECK_STREQ("Rejected due to Unacceptable BD_ADDR",
	    hci_status2str(0x0f));
	ATF_CHECK_STREQ("LMP PDU Not Allowed", hci_status2str(0x24));
	ATF_CHECK_STREQ("Link Key cannot be Changed", hci_status2str(0x26));

	/* 0x29 must remain the unit-key entry (was conflated with 0x26). */
	ATF_CHECK_STREQ("Pairing with unit key not supported",
	    hci_status2str(0x29));
}

ATF_TC_WITHOUT_HEAD(status_out_of_range);
ATF_TC_BODY(status_out_of_range, tc)
{
	/* Graceful fallback for negative and past-table-end codes. */
	ATF_CHECK_STREQ("Unknown error", hci_status2str(-1));
	ATF_CHECK_STREQ("Unknown error", hci_status2str(0x100));
}

/* ================================================================
 * Small enum/table formatters: every valid entry and both boundaries.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(enum_formatter_matrix);
ATF_TC_BODY(enum_formatter_matrix, tc)
{
	char	buf[128];
	int	i;

	for (i = 0; i < 2; i++) {
		ATF_CHECK_STREQ(i == 0 ? "SCO" : "ACL", hci_link2str(i));
		ATF_CHECK(strcmp("?", hci_pin2str(i)) != 0);
		ATF_CHECK(strcmp("?", hci_cc2str(i)) != 0);
		ATF_CHECK(strcmp("Unknown role", hci_role2str(i)) != 0);
	}
	for (i = 0; i < 3; i++) {
		ATF_CHECK(strcmp("?", hci_encrypt2str(i, 0)) != 0);
		ATF_CHECK(strcmp("?", hci_encrypt2str(i, 1)) != 0);
	}
	for (i = 0; i < 4; i++) {
		ATF_CHECK(strcmp("?", hci_scan2str(i)) != 0);
		ATF_CHECK(strcmp("?", hci_coding2str(i)) != 0);
		ATF_CHECK(strcmp("?", hci_vdata2str(i)) != 0);
		ATF_CHECK(strcmp("UNKNOWN", hci_con_state2str(i)) != 0);
		ATF_CHECK(strcmp("?", hci_addrtype2str(i)) != 0);
	}
	for (i = 0; i < 8; i++)
		ATF_CHECK(strcmp("Unknown accuracy", hci_mc_accuracy2str(i)) != 0);
	for (i = 0; i < 12; i++) {
		ATF_CHECK(strcmp("?", hci_ver2str(i)) != 0);
		ATF_CHECK(strcmp("?", hci_lmpver2str(i)) != 0);
	}

	ATF_CHECK_STREQ("?", hci_link2str(-1));
	ATF_CHECK_STREQ("?", hci_link2str(2));
	ATF_CHECK_STREQ("?", hci_pin2str(-1));
	ATF_CHECK_STREQ("?", hci_scan2str(4));
	ATF_CHECK_STREQ("?", hci_encrypt2str(3, 0));
	ATF_CHECK_STREQ("?", hci_encrypt2str(-1, 1));
	ATF_CHECK_STREQ("?", hci_coding2str(4));
	ATF_CHECK_STREQ("?", hci_vdata2str(-1));
	ATF_CHECK_STREQ("?", hci_ver2str(12));
	ATF_CHECK_STREQ("?", hci_lmpver2str(-1));
	ATF_CHECK_STREQ("?", hci_cc2str(2));
	ATF_CHECK_STREQ("UNKNOWN", hci_con_state2str(4));
	ATF_CHECK_STREQ("?", hci_addrtype2str(-1));
	ATF_CHECK_STREQ("Unknown role", hci_role2str(2));
	ATF_CHECK_STREQ("Unknown accuracy", hci_mc_accuracy2str(8));

	ATF_REQUIRE(hci_hmode2str(0x7, buf, sizeof(buf)) == buf);
	ATF_CHECK(strstr(buf, "Page") != NULL);
	ATF_CHECK(strstr(buf, "Inquiry") != NULL);
	ATF_CHECK(strstr(buf, "Periodic") != NULL);
	buf[0] = 'x';
	ATF_REQUIRE(hci_hmode2str(0, buf, 1) == buf);
	ATF_CHECK_STREQ("", buf);
	ATF_CHECK(hci_hmode2str(7, NULL, 0) == NULL);
}

ATF_TC_WITHOUT_HEAD(manufacturer_table_boundaries);
ATF_TC_BODY(manufacturer_table_boundaries, tc)
{
	int	i;

	/* Touch every assigned company identifier, not merely a sample. */
	for (i = 0; i < 2230; i++)
		ATF_CHECK(strcmp("?", hci_manufacturer2str(i)) != 0);
	ATF_CHECK_STREQ("Ericsson Technology Licensing",
	    hci_manufacturer2str(0));
	ATF_CHECK_STREQ("Boehringer Ingelheim Vetmedica GmbH",
	    hci_manufacturer2str(2229));
	ATF_CHECK_STREQ("?", hci_manufacturer2str(-1));
	ATF_CHECK_STREQ("?", hci_manufacturer2str(2230));
}

/* ================================================================
 * hci_commands2str: must not underflow/garble on the first set bit.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(commands_first_bit_no_underflow);
ATF_TC_BODY(commands_first_bit_no_underflow, tc)
{
	uint8_t	cmds[64];
	char	buf[4096];
	char const *r;

	memset(cmds, 0, sizeof(cmds));
	cmds[0] = 0x01;	/* octet 0, bit 0 == HCI_Inquiry */

	r = hci_commands2str(cmds, buf, sizeof(buf));
	ATF_REQUIRE(r == buf);

	/*
	 * Regression: with the running line-length uninitialized, the
	 * first set bit could take the 60-col wrap branch and execute
	 * buffer[-1] = '\n' (out-of-bounds write) and/or emit a leading
	 * newline.  A correctly initialized formatter starts with the
	 * command token, never a newline.
	 */
	ATF_CHECK(buf[0] != '\n');
	ATF_CHECK(strstr(buf, "Inquiry") != NULL);

	/* Empty bitmap -> empty string, no crash. */
	memset(cmds, 0, sizeof(cmds));
	r = hci_commands2str(cmds, buf, sizeof(buf));
	ATF_REQUIRE(r == buf);
	ATF_CHECK_STREQ("", buf);
}

ATF_TC_WITHOUT_HEAD(bitmap_formatter_matrix);
ATF_TC_BODY(bitmap_formatter_matrix, tc)
{
	uint8_t	bits[64];
	char	buf[16384];
	char	tiny[2] = { 'x', 'x' };

	memset(bits, 0xff, sizeof(bits));
	ATF_REQUIRE(hci_commands2str(bits, buf, sizeof(buf)) == buf);
	ATF_CHECK(strstr(buf, "HCI_Inquiry") != NULL);
	ATF_CHECK(strchr(buf, '\n') != NULL);
	ATF_REQUIRE(hci_commands2str(bits, tiny, sizeof(tiny)) == tiny);
	ATF_CHECK(tiny[1] == '\0');
	ATF_CHECK(hci_commands2str(bits, NULL, 0) == NULL);

	ATF_REQUIRE(hci_features2str(bits, buf, sizeof(buf)) == buf);
	ATF_CHECK(strstr(buf, "Encryption") != NULL);
	ATF_CHECK(strchr(buf, '\n') != NULL);
	ATF_REQUIRE(hci_features2str(bits, tiny, sizeof(tiny)) == tiny);
	ATF_CHECK(hci_features2str(bits, NULL, -1) == NULL);

	ATF_REQUIRE(hci_le_features2str(bits, buf, sizeof(buf)) == buf);
	ATF_CHECK(strstr(buf, "LE Encryption") != NULL);
	ATF_CHECK(strstr(buf, "Isochronous") != NULL);
	ATF_CHECK(strchr(buf, '\n') != NULL);
	ATF_REQUIRE(hci_le_features2str(bits, tiny, sizeof(tiny)) == tiny);
	ATF_CHECK(hci_le_features2str(bits, NULL, 0) == NULL);

	memset(bits, 0, sizeof(bits));
	ATF_REQUIRE(hci_features2str(bits, buf, sizeof(buf)) == buf);
	ATF_CHECK_STREQ("", buf);
	ATF_REQUIRE(hci_le_features2str(bits, buf, sizeof(buf)) == buf);
	ATF_CHECK_STREQ("", buf);
}

ATF_TC_WITHOUT_HEAD(bdaddr_formatter_matrix);
ATF_TC_BODY(bdaddr_formatter_matrix, tc)
{
	bdaddr_t	ba;

	memcpy(&ba, NG_HCI_BDADDR_ANY, sizeof(ba));
	ATF_CHECK_STREQ("*", hci_bdaddr2str(&ba));

	ATF_REQUIRE(bt_aton("01:23:45:67:89:ab", &ba));
	numeric_bdaddr = 1;
	ATF_CHECK_STREQ("01:23:45:67:89:ab", hci_bdaddr2str(&ba));
}

/* ================================================================
 * hci_le_chanmap2str: decode 40 map bits; write nothing to stdout.
 * ================================================================ */
ATF_TC_WITHOUT_HEAD(chanmap_decode_and_no_stdout);
ATF_TC_BODY(chanmap_decode_and_no_stdout, tc)
{
	uint8_t	map[5];
	char	buf[4096];
	char const *r;
	struct capture cap;

	/* All bits set: channels 0..39 present. */
	memset(map, 0xff, sizeof(map));

	capture_begin(&cap);
	r = hci_le_chanmap2str(map, buf, sizeof(buf));
	capture_end(&cap);

	ATF_REQUIRE(r == buf);

	/*
	 * Regression: this helper used to fprintf() the raw octets and a
	 * trailing newline to stdout, corrupting le_read_channel_map's
	 * formatted output.  A pure formatter must leave stdout untouched.
	 */
	ATF_CHECK_STREQ("", cap.buf);

	/* LSB-first: channel 0 and the top channel 39 must both decode. */
	ATF_CHECK(strstr(buf, "00 ") != NULL);
	ATF_CHECK(strstr(buf, "39 ") != NULL);

	/* Empty map -> no channels, still nothing on stdout. */
	memset(map, 0, sizeof(map));
	capture_begin(&cap);
	r = hci_le_chanmap2str(map, buf, sizeof(buf));
	capture_end(&cap);
	ATF_REQUIRE(r == buf);
	ATF_CHECK_STREQ("", cap.buf);
	ATF_CHECK_STREQ("", buf);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, status_error_strings);
	ATF_TP_ADD_TC(tp, status_out_of_range);
	ATF_TP_ADD_TC(tp, enum_formatter_matrix);
	ATF_TP_ADD_TC(tp, manufacturer_table_boundaries);
	ATF_TP_ADD_TC(tp, commands_first_bit_no_underflow);
	ATF_TP_ADD_TC(tp, bitmap_formatter_matrix);
	ATF_TP_ADD_TC(tp, bdaddr_formatter_matrix);
	ATF_TP_ADD_TC(tp, chanmap_decode_and_no_stdout);
	return (atf_no_error());
}
